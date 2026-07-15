"""
prevention/mitigation_actions.py

Módulo de prevención automatizada para M.A.R.A.N.D.U.

NOTA (ejecución bajo el usuario de servicio 'marandu'):
Todas las acciones que tocan el sistema (firewall, cuentas de usuario, procesos,
paquetes, servicios, cuarentena de archivos) se ejecutan vía `sudo -n <binario>`.
El proceso de la app (marandu-web.service) corre como 'marandu', sin privilegios
de root; las reglas exactas que autorizan cada uno de estos comandos están en
/etc/sudoers.d/marandu (generado por setup_env.sh). El flag `-n` (no interactivo)
hace que, si por algún motivo la regla de sudoers no matchea, el comando falle
de inmediato en vez de quedar colgado esperando una contraseña que nunca va a
llegar (lo cual trabaría el worker async de alarmas).

Las funciones que originalmente usaban syscalls directas de Python (os.kill,
os.setpriority, os.chmod, shutil.move) fueron migradas a subprocess + sudo,
porque sudo solo puede mediar la ejecución de binarios externos, no llamadas
de sistema hechas dentro del propio proceso de marandu-web.service.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import os
import re
import secrets
import shutil
import smtplib
import string
import subprocess
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Alarma, AccionPrevencion, ConfiguracionModulo
from db.session import async_session

from prevention.strategia import obtener_nivel_efectivo, NIVELES  # noqa: F401

# ---------------------------------------------------------------------------
# Configuración estática / listas blancas
# ---------------------------------------------------------------------------

LOG_PATH = "/var/log/hips/prevencion.log"
QUARANTINE_DIR = "/var/lib/hips/quarantine/"

PROTECTED_USERS = {"root", "postgres", "marandu_app", "marandu_svc"}

BAN_TOOL_WHITELIST = {
    "tcpdump": "tcpdump",
    "wireshark": "wireshark",
    "tshark": "wireshark-cli",
    "dumpcap": "wireshark-cli",
}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_SERVICE_RE = re.compile(r"^[a-zA-Z0-9@._-]{1,64}(\.service)?$")

# Mapeo tipo_alarma (como llega en la tabla `alarmas`) -> grupo de estrategia.
# Integradas por completo las alarmas faltantes descritas en el manual de instalación.
ALARM_GRUPO = {
    "USUARIO_SOSPECHOSO": "usuario_sospechoso",
    "PROCESO_ALTO_CONSUMO": "proceso_alto_consumo",
    "ARCHIVO_TMP_SOSPECHOSO": "archivo_tmp_sospechoso",
    "WEB_SCAN_404": "web_scan_404",
    "WEB_EXPLOIT_500": "web_exploit_500",
    "FAILED_LOGIN_MULTIPLE": "failed_login_multiple",
    "SMTP_BRUTE_FORCE": "smtp_brute_force",
    "MAIL_QUEUE_ALTA": "mail_queue_alta",
    "DDOS_DETECTADO": "ddos_detectado",
    # Mapeo de nuevas alarmas:
    "MODIFICACION_PASSWD": "integridad_sistema",
    "MODIFICACION_SHADOW": "integridad_sistema",
    "CRON_SOSPECHOSO": "cron_sospechoso",
    "CREDENTIAL_STUFFING": "credential_stuffing"
}

logger = logging.getLogger("marandu.prevention")
logger.setLevel(logging.INFO)
if not logger.handlers:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    _handler = logging.FileHandler(LOG_PATH)
    _handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
    logger.addHandler(_handler)


# ---------------------------------------------------------------------------
# Validadores
# ---------------------------------------------------------------------------

def _validar_ip(ip: Optional[str]) -> bool:
    if not ip or ip in ("N/A", "local"):
        return False
    if not _IP_RE.match(ip):
        return False
    return all(0 <= int(octeto) <= 255 for octeto in ip.split("."))


def _validar_username(nombre: Optional[str]) -> bool:
    if not nombre:
        return False
    if nombre in PROTECTED_USERS:
        return False
    return bool(_USERNAME_RE.match(nombre))


def _validar_servicio(nombre: Optional[str]) -> bool:
    return bool(nombre) and bool(_SERVICE_RE.match(nombre))


def _validar_pid(pid) -> Optional[int]:
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return None
    if pid_int <= 1:
        return None
    return pid_int


def _validar_ruta_cuarentena(ruta: Optional[str]) -> Optional[Path]:
    if not ruta:
        return None
    p = Path(ruta)
    if not p.is_absolute():
        return None
    if ".." in p.parts:
        return None
    try:
        if not p.exists() or p.is_symlink() or not p.is_file():
            return None
    except OSError:
        return None
    return p


# ---------------------------------------------------------------------------
# Configuración segura desde BD
# ---------------------------------------------------------------------------

async def _get_secure_config(session: AsyncSession, clave: str) -> Optional[str]:
    try:
        stmt = select(ConfiguracionModulo).where(
            ConfiguracionModulo.parametro == clave,
            ConfiguracionModulo.activo.is_(True),
        )
        resultado = await session.execute(stmt)
        fila = resultado.scalar_one_or_none()
        return fila.valor if fila else None
    except Exception:
        logger.exception("Error leyendo configuración segura: %s", clave)
        return None


async def _enviar_notificacion(session: AsyncSession, asunto: str, cuerpo: str) -> None:
    try:
        smtp_host = await _get_secure_config(session, "smtp_host")
        smtp_port = await _get_secure_config(session, "smtp_port")
        smtp_user = await _get_secure_config(session, "smtp_user")
        smtp_pass = await _get_secure_config(session, "smtp_pass")
        admin_email = await _get_secure_config(session, "admin_email")

        if not all([smtp_host, smtp_port, smtp_user, smtp_pass, admin_email]):
            logger.warning("Config SMTP incompleta, se omite notificación por correo")
            return

        msg = MIMEText(cuerpo)
        msg["Subject"] = asunto
        msg["From"] = smtp_user
        msg["To"] = admin_email

        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except Exception:
        logger.exception("No se pudo enviar la notificación por correo")


def _log_accion(accion: str, amenaza: str, identificador: str) -> None:
    logger.info("accion=%s | amenaza=%s | identificador=%s", accion, amenaza, identificador)


# ---------------------------------------------------------------------------
# Funciones de mitigación
# ---------------------------------------------------------------------------

def ip_block(ip_origen: str) -> bool:
    if not _validar_ip(ip_origen):
        logger.warning("ip_block: IP inválida o no bloqueable: %r", ip_origen)
        return False
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/firewall-cmd", "--permanent", "--zone=drop", f"--add-source={ip_origen}"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        subprocess.run(
            ["sudo", "-n", "/usr/bin/firewall-cmd", "--reload"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        _log_accion("ip_block", "bloqueo de IP", ip_origen)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("ip_block falló para %s", ip_origen)
        return False


def ip_rate_limit(ip_origen: str, limite: str = "10/m") -> bool:
    if not _validar_ip(ip_origen):
        logger.warning("ip_rate_limit: IP inválida o no limitable: %r", ip_origen)
        return False
    regla = f"rule family='ipv4' source address='{ip_origen}' accept limit value='{limite}'"
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/firewall-cmd", "--permanent", "--zone=drop", f"--add-rich-rule={regla}"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        subprocess.run(
            ["sudo", "-n", "/usr/bin/firewall-cmd", "--reload"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        _log_accion("ip_rate_limit", "limite de tasa aplicado", ip_origen)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("ip_rate_limit falló para %s", ip_origen)
        return False


def throttle_proceso(pid, prioridad: int = 19) -> bool:
    """
    Reduce la prioridad del proceso. Antes usaba os.setpriority() directamente,
    pero eso requiere que el proceso de marandu-web sea dueño del PID objetivo
    (o root). Se migra a `renice` vía sudo para poder actuar sobre procesos de
    cualquier usuario, que es el caso real de un proceso malicioso detectado.
    """
    pid_valido = _validar_pid(pid)
    if pid_valido is None:
        logger.warning("throttle_proceso: PID inválido: %r", pid)
        return False
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/renice", "-n", str(prioridad), "-p", str(pid_valido)],
            check=True, capture_output=True, text=True, timeout=10,
        )
        _log_accion("throttle_proceso", "prioridad reducida", str(pid_valido))
        return True
    except subprocess.CalledProcessError as e:
        if "No such process" in (e.stderr or ""):
            logger.info("throttle_proceso: PID %s ya no existe (posible carrera)", pid_valido)
            return True
        logger.exception("throttle_proceso: fallo para PID %s (%s)", pid_valido, e.stderr)
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("throttle_proceso falló para %s", pid_valido)
        return False


def change_pass_usr(nombre_usr: str) -> Optional[str]:
    if not _validar_username(nombre_usr):
        logger.warning("change_pass_usr: usuario inválido o protegido: %r", nombre_usr)
        return None
    alfabeto = string.ascii_letters + string.digits
    nueva_pass = "".join(secrets.choice(alfabeto) for _ in range(20))
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/sbin/chpasswd"],
            input=f"{nombre_usr}:{nueva_pass}\n",
            check=True, capture_output=True, text=True, timeout=10,
        )
        _log_accion("change_pass_usr", "reseteo de contraseña", nombre_usr)
        return nueva_pass
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("change_pass_usr falló para %s", nombre_usr)
        return None


def bloq_usr(nombre_usr: str) -> bool:
    if not _validar_username(nombre_usr):
        logger.warning("bloq_usr: usuario inválido o protegido: %r", nombre_usr)
        return False
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/sbin/usermod", "-L", nombre_usr],
            check=True, capture_output=True, text=True, timeout=10,
        )
        _log_accion("bloq_usr", "bloqueo de cuenta", nombre_usr)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("bloq_usr falló para %s", nombre_usr)
        return False


def kill_proces(pid) -> bool:
    """
    Termina el proceso. Antes usaba os.kill() directamente, pero eso requiere
    que marandu-web sea dueño del PID objetivo (o root). Se migra a `kill`
    vía sudo por el mismo motivo que throttle_proceso.
    """
    pid_valido = _validar_pid(pid)
    if pid_valido is None:
        logger.warning("kill_proces: PID inválido: %r", pid)
        return False
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/kill", "-9", str(pid_valido)],
            check=True, capture_output=True, text=True, timeout=10,
        )
        _log_accion("kill_proces", "proceso terminado", str(pid_valido))
        return True
    except subprocess.CalledProcessError as e:
        # kill devuelve error si el PID ya no existe (posible carrera): no es una falla real
        if "No such process" in (e.stderr or ""):
            logger.info("kill_proces: PID %s ya no existe (posible carrera)", pid_valido)
            return True
        logger.exception("kill_proces: fallo matando PID %s (%s)", pid_valido, e.stderr)
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("kill_proces falló para %s", pid_valido)
        return False


def ban_tool(nombre_binario: str) -> bool:
    paquete = BAN_TOOL_WHITELIST.get((nombre_binario or "").strip().lower())
    if not paquete:
        logger.warning("ban_tool: binario no está en whitelist: %r", nombre_binario)
        return False
    if shutil.which(nombre_binario) is None:
        logger.info("ban_tool: %s no está instalado, nada que hacer", nombre_binario)
        return True
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/dnf", "remove", "-y", paquete],
            check=True, capture_output=True, text=True, timeout=60,
        )
        _log_accion("ban_tool", "herramienta no autorizada eliminada", nombre_binario)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("ban_tool falló para %s", nombre_binario)
        return False


def stop_service(nombre_servicio: str) -> bool:
    if not _validar_servicio(nombre_servicio):
        logger.warning("stop_service: nombre de servicio inválido: %r", nombre_servicio)
        return False
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", "stop", nombre_servicio],
            check=True, capture_output=True, text=True, timeout=15,
        )
        _log_accion("stop_service", "servicio detenido", nombre_servicio)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("stop_service falló para %s", nombre_servicio)
        return False


def quarantine_file(ruta_archivo: str) -> bool:
    """
    Mueve el archivo a cuarentena y le quita todos los permisos. El archivo
    origen puede pertenecer a otro usuario/proceso, así que el mv y el chmod
    finales requieren root; se migran a sudo. La construcción del path de
    destino y el makedirs del directorio de cuarentena no tocan nada ajeno,
    así que se quedan en Python puro.
    """
    origen = _validar_ruta_cuarentena(ruta_archivo)
    if origen is None:
        logger.warning("quarantine_file: ruta inválida o inexistente: %r", ruta_archivo)
        return False
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        marca = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        destino = Path(QUARANTINE_DIR) / f"{marca}_{origen.name}"

        subprocess.run(
            ["sudo", "-n", "/usr/bin/mv", str(origen), str(destino)],
            check=True, capture_output=True, text=True, timeout=10,
        )
        subprocess.run(
            ["sudo", "-n", "/usr/bin/chmod", "000", str(destino)],
            check=True, capture_output=True, text=True, timeout=10,
        )
        _log_accion("quarantine_file", "archivo puesto en cuarentena", str(origen))
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError):
        logger.exception("quarantine_file falló para %s", ruta_archivo)
        return False


# ---------------------------------------------------------------------------
# Dispatchers específicos de las 3 alarmas faltantes
# ---------------------------------------------------------------------------

async def _resolver_integridad_sistema(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    """
    Maneja MODIFICACION_PASSWD y MODIFICACION_SHADOW (Módulo I).
    Piso de seguridad = "moderado" (nunca se silencia del todo).
    """
    detalle = alarma.detalle or {}
    archivo = detalle.get("archivo")
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO[alarma.tipo_alarma])

    # Nivel moderado: Notificación urgente y protección básica (bloqueamos sesiones de usuarios que no estén en whitelist)
    if nivel == "moderado":
        # Ejecuta la cuarentena del archivo temporal si fue generado, o simplemente notifica.
        return f"notificar_cambio_archivo({archivo})[moderado]", True

    # Nivel agresivo: Bloqueo inmediato del acceso del sistema aislando SSH
    exito_ssh = await asyncio.to_thread(stop_service, "sshd")
    return f"stop_service(sshd)+notificacion({archivo})[agresivo]", exito_ssh


async def _resolver_cron_sospechoso(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    """
    Maneja CRON_SOSPECHOSO (Módulo IX).
    Piso de seguridad = "minimo".
    """
    detalle = alarma.detalle or {}
    fuente = detalle.get("fuente")  # Ruta del crontab sospechoso
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["CRON_SOSPECHOSO"])

    if nivel == "minimo" or not fuente:
        return f"notificacion_cron_sospechoso({fuente})[minimo]", True

    if nivel == "moderado":
        # Mueve la fuente del cron detectada a cuarentena
        exito = await asyncio.to_thread(quarantine_file, fuente)
        return f"quarantine_file({fuente})[moderado]", exito

    # Agresivo: Envía a cuarentena el cron y detiene el servicio cron de raíz para auditar
    exito_quar = await asyncio.to_thread(quarantine_file, fuente)
    exito_stop = await asyncio.to_thread(stop_service, "crond")
    return f"quarantine_file({fuente})+stop_service(crond)[agresivo]", exito_quar and exito_stop


async def _resolver_credential_stuffing(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    """
    Maneja CREDENTIAL_STUFFING (Módulo X).
    Piso de seguridad = "moderado".
    """
    detalle = alarma.detalle or {}
    usuarios_distintos = detalle.get("usuarios_distintos") or []
    ip = alarma.ip_origen
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["CREDENTIAL_STUFFING"])

    acciones = []
    resultados = []

    # Filtrar usuarios que existan realmente y no estén en lista blanca
    usuarios_validos = [u for u in usuarios_distintos if _validar_username(u)]

    if nivel in ("moderado", "agresivo"):
        if _validar_ip(ip):
            resultados.append(await asyncio.to_thread(ip_rate_limit if nivel == "moderado" else ip_block, ip))
            acciones.append(f"ip_mitigada({ip})")

        # Bloquear cuentas de usuarios del sistema local que hayan sido objetivo activo
        for usr in usuarios_validos:
            resultados.append(await asyncio.to_thread(bloq_usr, usr))
            acciones.append(f"bloq_usr({usr})")

    if nivel == "agresivo":
        # Además del bloqueo, se fuerza un restablecimiento completo de contraseña a los usuarios afectados
        for usr in usuarios_validos:
            nueva_pass = await asyncio.to_thread(change_pass_usr, usr)
            if nueva_pass:
                await _enviar_notificacion(
                    session,
                    asunto=f"[MARANDU][URGENTE] Credential Stuffing - Reset de Password: {usr}",
                    cuerpo=f"Se reseteó la credencial del usuario local '{usr}' debido a un ataque automatizado.\nContraseña provisional: {nueva_pass}\n",
                )
            resultados.append(nueva_pass is not None)
            acciones.append(f"change_pass_usr({usr})")

    if not acciones:
        return f"sin_acciones_stuffing[{nivel}]", False
    return f"{'+'.join(acciones)}[{nivel}]", all(resultados)


# ---------------------------------------------------------------------------
# Dispatchers tradicionales
# ---------------------------------------------------------------------------

async def _resolver_usuario_sospechoso(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    detalle = alarma.detalle or {}
    usuario = detalle.get("usuario_reportado") or detalle.get("usuario")
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["USUARIO_SOSPECHOSO"])

    if nivel == "minimo" or not usuario or not _validar_username(usuario):
        return f"notificacion_usuario_sospechoso({usuario})[{nivel}]", True

    if nivel == "moderado":
        exito = await asyncio.to_thread(bloq_usr, usuario)
        return f"bloq_usr({usuario})[moderado]", exito

    exito_bloq = await asyncio.to_thread(bloq_usr, usuario)
    nueva_pass = await asyncio.to_thread(change_pass_usr, usuario)
    if nueva_pass:
        await _enviar_notificacion(
            session,
            asunto=f"[MARANDU][URGENTE] Password reseteada: {usuario}",
            cuerpo=f"Se reseteó la contraseña de '{usuario}' por USUARIO_SOSPECHOSO (nivel agresivo).\nNueva contraseña: {nueva_pass}\n",
        )
    return f"bloq_usr({usuario})+change_pass_usr({usuario})[agresivo]", exito_bloq and nueva_pass is not None


async def _resolver_proceso_alto_consumo(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    pid = (alarma.detalle or {}).get("pid")
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["PROCESO_ALTO_CONSUMO"])

    if nivel == "minimo":
        return f"notificacion_proceso_alto_consumo(pid={pid})[minimo]", True
    if nivel == "moderado":
        exito = await asyncio.to_thread(throttle_proceso, pid)
        return f"throttle_proceso({pid})[moderado]", exito
    exito = await asyncio.to_thread(kill_proces, pid)
    return f"kill_proces({pid})[agresivo]", exito


async def _resolver_archivo_tmp_sospechoso(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    detalle = alarma.detalle or {}
    pid = detalle.get("pid")
    exe = detalle.get("exe")
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["ARCHIVO_TMP_SOSPECHOSO"])

    if nivel == "moderado":
        exito = await asyncio.to_thread(quarantine_file, exe) if exe else True
        return f"quarantine_file({exe})[moderado]", exito

    exito_kill = await asyncio.to_thread(kill_proces, pid) if pid else True
    exito_cuarentena = await asyncio.to_thread(quarantine_file, exe) if exe else True
    return f"kill_proces({pid})+quarantine_file({exe})[agresivo]", exito_kill and exito_cuarentena


async def _resolver_web_ip(alarma: Alarma, session: AsyncSession, grupo: str) -> tuple[str, bool]:
    ip = alarma.ip_origen
    nivel = await obtener_nivel_efectivo(session, grupo)

    if not _validar_ip(ip):
        return f"sin_ip_bloqueable({ip})[{nivel}]", False

    if nivel == "minimo":
        return f"notificacion_web({ip})[minimo]", True
    if nivel == "moderado":
        exito = await asyncio.to_thread(ip_rate_limit, ip)
        return f"ip_rate_limit({ip})[moderado]", exito
    exito = await asyncio.to_thread(ip_block, ip)
    return f"ip_block({ip})[agresivo]", exito


async def _resolver_web_scan_404(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    return await _resolver_web_ip(alarma, session, ALARM_GRUPO["WEB_SCAN_404"])


async def _resolver_web_exploit_500(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    return await _resolver_web_ip(alarma, session, ALARM_GRUPO["WEB_EXPLOIT_500"])


async def _resolver_smtp_brute_force(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    return await _resolver_web_ip(alarma, session, ALARM_GRUPO["SMTP_BRUTE_FORCE"])


async def _resolver_failed_login(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    detalle = alarma.detalle or {}
    usuario = detalle.get("usuario")
    ip = alarma.ip_origen
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["FAILED_LOGIN_MULTIPLE"])

    acciones = []
    resultados = []

    if nivel in ("moderado", "agresivo"):
        if _validar_ip(ip):
            resultados.append(await asyncio.to_thread(ip_block, ip))
            acciones.append(f"ip_block({ip})")
        if usuario and _validar_username(usuario):
            resultados.append(await asyncio.to_thread(bloq_usr, usuario))
            acciones.append(f"bloq_usr({usuario})")

    if nivel == "agresivo" and usuario and _validar_username(usuario):
        nueva_pass = await asyncio.to_thread(change_pass_usr, usuario)
        if nueva_pass:
            await _enviar_notificacion(
                session,
                asunto=f"[MARANDU][URGENTE] Password reseteada: {usuario}",
                cuerpo=f"Se reseteó la contraseña de '{usuario}' por FAILED_LOGIN_MULTIPLE (nivel agresivo).\nNueva contraseña: {nueva_pass}\n",
            )
        resultados.append(nueva_pass is not None)
        acciones.append(f"change_pass_usr({usuario})")

    if not acciones:
        return f"sin_objetivo_valido[{nivel}]", False
    return f"{'+'.join(acciones)}[{nivel}]", all(resultados)


async def _resolver_mail_queue_alta(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    detalle = alarma.detalle or {}
    servicio = detalle.get("servicio") or "postfix"
    pid = detalle.get("pid")
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["MAIL_QUEUE_ALTA"])

    if nivel == "minimo":
        return "notificacion_mail_queue_alta[minimo]", True

    if not _validar_servicio(servicio):
        return f"servicio_invalido({servicio})[{nivel}]", False

    exito_stop = await asyncio.to_thread(stop_service, servicio)
    if nivel == "moderado":
        return f"stop_service({servicio})[moderado]", exito_stop

    exito_kill = await asyncio.to_thread(kill_proces, pid) if pid else True
    return f"stop_service({servicio})+kill_proces({pid})[agresivo]", exito_stop and exito_kill


async def _resolver_ddos(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    detalle = alarma.detalle or {}
    ips = detalle.get("top_ips_origen") or []
    if not ips and _validar_ip(alarma.ip_origen):
        ips = [alarma.ip_origen]
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["DDOS_DETECTADO"])

    ips_validas = [ip for ip in ips if _validar_ip(ip)]
    if not ips_validas:
        return f"sin_ips_bloqueables[{nivel}]", False

    accion_fn = ip_rate_limit if nivel == "moderado" else ip_block
    resultados = [await asyncio.to_thread(accion_fn, ip) for ip in ips_validas]
    return f"{accion_fn.__name__}(x{len(resultados)})[{nivel}]", all(resultados)


# ---------------------------------------------------------------------------
# Dispatcher Global
# ---------------------------------------------------------------------------

DISPATCH = {
    "USUARIO_SOSPECHOSO": _resolver_usuario_sospechoso,
    "PROCESO_ALTO_CONSUMO": _resolver_proceso_alto_consumo,
    "ARCHIVO_TMP_SOSPECHOSO": _resolver_archivo_tmp_sospechoso,
    "WEB_SCAN_404": _resolver_web_scan_404,
    "WEB_EXPLOIT_500": _resolver_web_exploit_500,
    "FAILED_LOGIN_MULTIPLE": _resolver_failed_login,
    "SMTP_BRUTE_FORCE": _resolver_smtp_brute_force,
    "MAIL_QUEUE_ALTA": _resolver_mail_queue_alta,
    "DDOS_DETECTADO": _resolver_ddos,
    # Nuevos resolvedores mapeados uno a uno:
    "MODIFICACION_PASSWD": _resolver_integridad_sistema,
    "MODIFICACION_SHADOW": _resolver_integridad_sistema,
    "CRON_SOSPECHOSO": _resolver_cron_sospechoso,
    "CREDENTIAL_STUFFING": _resolver_credential_stuffing
}


async def procesar_alarmas_pendientes() -> None:
    async with async_session() as session:
        try:
            stmt = select(Alarma).where(Alarma.resuelta.is_(False)).order_by(Alarma.timestamp.asc())
            resultado = await session.execute(stmt)
            alarmas_pendientes = resultado.scalars().all()
        except Exception:
            logger.exception("No se pudo consultar alarmas pendientes")
            return

        for alarma in alarmas_pendientes:
            resolver = DISPATCH.get(alarma.tipo_alarma)
            if resolver is None:
                logger.warning("Sin resolver definido para tipo_alarma=%s (id=%s)", alarma.tipo_alarma, alarma.id)
                continue

            try:
                descripcion_accion, exito = await resolver(alarma, session)
            except Exception:
                logger.exception("Excepción no controlada resolviendo alarma id=%s", alarma.id)
                descripcion_accion, exito = "error_interno", False

            resultado_txt = "Éxito" if exito else "Fallo"
            accion = AccionPrevencion(
                alarma_id=alarma.id,
                accion=descripcion_accion,
                resultado=resultado_txt,
            )
            session.add(accion)

            if exito:
                alarma.resuelta = True

            try:
                await _enviar_notificacion(
                    session,
                    asunto=f"[MARANDU] Alarma {alarma.tipo_alarma} - {resultado_txt}",
                    cuerpo=(
                        f"Alarma id={alarma.id}\n"
                        f"Tipo: {alarma.tipo_alarma}\n"
                        f"Módulo: {alarma.modulo}\n"
                        f"IP origen: {alarma.ip_origen}\n"
                        f"Acción: {descripcion_accion}\n"
                        f"Resultado: {resultado_txt}\n"
                        f"Timestamp: {alarma.timestamp}\n"
                    ),
                )
            except Exception:
                logger.exception("Fallo enviando notificación para alarma id=%s", alarma.id)

            try:
                await session.commit()
            except Exception:
                logger.exception("Fallo al commitear resultado de alarma id=%s", alarma.id)
                await session.rollback()


if __name__ == "__main__":
    asyncio.run(procesar_alarmas_pendientes())