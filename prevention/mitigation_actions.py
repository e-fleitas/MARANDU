"""
prevention/mitigation_actions.py

Módulo de prevención automatizada para M.A.R.A.N.D.U.

Responsabilidades:
  1. Exponer las funciones de mitigación de bajo nivel (ip_block, kill_proces, etc.)
     usando subprocess sin shell=True y con validación estricta de entrada.
  2. Exponer un dispatcher (`procesar_alarmas_pendientes`) que lee `alarmas` con
     resuelta=False, matchea por tipo_alarma según la tabla de mapeo del equipo,
     extrae argumentos del detalle JSONB y ejecuta la mitigación correspondiente
     en el nivel (minimo/moderado/agresivo) que indique `strategia.py` para ese
     grupo de alarma.

Reglas de seguridad aplicadas:
  - Nunca se usa shell=True ni se interpola strings de usuario en comandos.
  - Toda entrada proveniente de `detalle` (JSONB) se valida contra un formato
    esperado ANTES de tocar el sistema operativo.
  - Listas blancas para usuarios protegidos y binarios elegibles a desinstalar.
  - Fail-safe: cualquier excepción se captura, se loguea y NO rompe el ciclo
    del dispatcher (una alarma rota no debe frenar el procesamiento del resto).
  - `resuelta` solo pasa a True si la mitigación fue exitosa; si falla, queda
    en False para reintento en el próximo ciclo del scheduler.
  - El nivel a ejecutar se obtiene con `obtener_nivel_efectivo`, que aplica un
    piso de severidad por grupo (ver strategia.py): las alarmas de explotación
    activa nunca pueden quedar en "minimo" (solo notificación) aunque la
    configuración en BD diga lo contrario. Esto evita que un atacante que
    comprometa el panel de configuración silencie la respuesta automática.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import os
import re
import secrets
import shutil
import signal
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

# Import relativo: ajustar según la ubicación real del módulo en el proyecto
# (el docstring de strategia.py sugiere prevention/estrategias.py; el archivo
# subido se llama strategia.py, así que se importa por ese nombre).
from prevention.strategia import obtener_nivel_efectivo, NIVELES  # noqa: F401

# ---------------------------------------------------------------------------
# Configuración estática / listas blancas
# ---------------------------------------------------------------------------

LOG_PATH = "/var/log/hips/prevencion.log"
QUARANTINE_DIR = "/var/lib/hips/quarantine/"

# Usuarios que el módulo NUNCA debe bloquear ni resetear, sin importar qué
# diga la alarma. Ajustar según cuentas reales del sistema.
PROTECTED_USERS = {"root", "postgres", "marandu_app", "marandu_svc"}

# Mapeo binario -> paquete dnf, para no ejecutar `dnf remove` con un nombre
# arbitrario que llegue en el detalle de la alarma.
BAN_TOOL_WHITELIST = {
    "tcpdump": "tcpdump",
    "wireshark": "wireshark",
    "tshark": "wireshark-cli",
    "dumpcap": "wireshark-cli",
}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_SERVICE_RE = re.compile(r"^[a-zA-Z0-9@._-]{1,64}(\.service)?$")

# Mapeo tipo_alarma (como llega en la tabla `alarmas`) -> grupo de estrategia
# (como está guardado en `configuracion_modulos.modulo`). Es la clave que
# conecta el dispatcher con el nivel minimo/moderado/agresivo configurado.
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
    if pid_int <= 1:  # nunca tocar PID 0/1 (init/kernel)
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
    """Lee un parámetro de configuración desde ConfiguracionModulo (activo=True)."""
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
    """Envía un correo de notificación al admin. Falla en silencio (no rompe el flujo)."""
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
# Funciones de mitigación (síncronas, subprocess seguro)
# ---------------------------------------------------------------------------

def ip_block(ip_origen: str) -> bool:
    if not _validar_ip(ip_origen):
        logger.warning("ip_block: IP inválida o no bloqueable: %r", ip_origen)
        return False
    try:
        subprocess.run(
            ["firewall-cmd", "--permanent", "--zone=drop", f"--add-source={ip_origen}"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        subprocess.run(
            ["firewall-cmd", "--reload"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        _log_accion("ip_block", "bloqueo de IP", ip_origen)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("ip_block falló para %s", ip_origen)
        return False


def ip_rate_limit(ip_origen: str, limite: str = "10/m") -> bool:
    """
    Mitigación 'moderada' para tráfico web/mail sospechoso pero no
    confirmado como ataque: en vez de cortar la IP por completo, limita
    la tasa de conexiones aceptadas. No penaliza a un usuario legítimo
    que accede ocasionalmente, pero frena el abuso automatizado.
    `limite` es un valor fijo interno (no proviene del detalle de la
    alarma), así que no hay riesgo de inyección vía ese parámetro.
    """
    if not _validar_ip(ip_origen):
        logger.warning("ip_rate_limit: IP inválida o no limitable: %r", ip_origen)
        return False
    regla = f"rule family='ipv4' source address='{ip_origen}' accept limit value='{limite}'"
    try:
        subprocess.run(
            ["firewall-cmd", "--permanent", "--zone=drop", f"--add-rich-rule={regla}"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        subprocess.run(
            ["firewall-cmd", "--reload"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        _log_accion("ip_rate_limit", "limite de tasa aplicado", ip_origen)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("ip_rate_limit falló para %s", ip_origen)
        return False


def throttle_proceso(pid, prioridad: int = 19) -> bool:
    """
    Mitigación 'moderada' para PROCESO_ALTO_CONSUMO: no mata el proceso
    (podría ser legítimo), solo le baja la prioridad de planificación al
    mínimo para que no acapare CPU frente a otros procesos. Reversible
    (el proceso sigue vivo, solo corre más lento bajo contención).
    """
    pid_valido = _validar_pid(pid)
    if pid_valido is None:
        logger.warning("throttle_proceso: PID inválido: %r", pid)
        return False
    try:
        os.setpriority(os.PRIO_PROCESS, pid_valido, prioridad)
        _log_accion("throttle_proceso", "prioridad reducida", str(pid_valido))
        return True
    except ProcessLookupError:
        logger.info("throttle_proceso: PID %s ya no existe (posible carrera)", pid_valido)
        return True
    except PermissionError:
        logger.exception("throttle_proceso: permisos insuficientes para PID %s", pid_valido)
        return False


def change_pass_usr(nombre_usr: str) -> Optional[str]:
    """Devuelve la nueva contraseña si tuvo éxito (para incluirla en el correo), o None."""
    if not _validar_username(nombre_usr):
        logger.warning("change_pass_usr: usuario inválido o protegido: %r", nombre_usr)
        return None
    alfabeto = string.ascii_letters + string.digits
    nueva_pass = "".join(secrets.choice(alfabeto) for _ in range(20))
    try:
        subprocess.run(
            ["chpasswd"],
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
            ["usermod", "-L", nombre_usr],
            check=True, capture_output=True, text=True, timeout=10,
        )
        _log_accion("bloq_usr", "bloqueo de cuenta", nombre_usr)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("bloq_usr falló para %s", nombre_usr)
        return False


def kill_proces(pid) -> bool:
    pid_valido = _validar_pid(pid)
    if pid_valido is None:
        logger.warning("kill_proces: PID inválido: %r", pid)
        return False
    try:
        os.kill(pid_valido, signal.SIGKILL)
        _log_accion("kill_proces", "proceso terminado", str(pid_valido))
        return True
    except ProcessLookupError:
        logger.info("kill_proces: PID %s ya no existe (posible carrera)", pid_valido)
        return True  # el objetivo (proceso muerto) ya se cumplió
    except PermissionError:
        logger.exception("kill_proces: permisos insuficientes para PID %s", pid_valido)
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
            ["dnf", "remove", "-y", paquete],
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
            ["systemctl", "stop", nombre_servicio],
            check=True, capture_output=True, text=True, timeout=15,
        )
        _log_accion("stop_service", "servicio detenido", nombre_servicio)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        logger.exception("stop_service falló para %s", nombre_servicio)
        return False


def quarantine_file(ruta_archivo: str) -> bool:
    origen = _validar_ruta_cuarentena(ruta_archivo)
    if origen is None:
        logger.warning("quarantine_file: ruta inválida o inexistente: %r", ruta_archivo)
        return False
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        marca = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        destino = Path(QUARANTINE_DIR) / f"{marca}_{origen.name}"
        shutil.move(str(origen), str(destino))
        os.chmod(destino, 0o000)
        _log_accion("quarantine_file", "archivo puesto en cuarentena", str(origen))
        return True
    except OSError:
        logger.exception("quarantine_file falló para %s", ruta_archivo)
        return False


# ---------------------------------------------------------------------------
# Dispatcher: extracción de argumentos + resolución por tipo_alarma
# ---------------------------------------------------------------------------

async def _resolver_usuario_sospechoso(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    detalle = alarma.detalle or {}
    usuario = detalle.get("usuario_reportado") or detalle.get("usuario")
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["USUARIO_SOSPECHOSO"])

    if nivel == "minimo" or not usuario or not _validar_username(usuario):
        return f"notificacion_usuario_sospechoso({usuario})[{nivel}]", True

    if nivel == "moderado":
        # Bloquea la cuenta (reversible con usermod -U) sin tocar la password.
        exito = await asyncio.to_thread(bloq_usr, usuario)
        return f"bloq_usr({usuario})[moderado]", exito

    # agresivo: bloquear la cuenta Y rotar la contraseña, para forzar
    # re-provisionamiento manual antes de reactivarla.
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
    # Piso del grupo = "moderado", así que nivel nunca llega a "minimo" acá.
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["ARCHIVO_TMP_SOSPECHOSO"])

    if nivel == "moderado":
        exito = await asyncio.to_thread(quarantine_file, exe) if exe else True
        return f"quarantine_file({exe})[moderado]", exito

    exito_kill = await asyncio.to_thread(kill_proces, pid) if pid else True
    exito_cuarentena = await asyncio.to_thread(quarantine_file, exe) if exe else True
    return f"kill_proces({pid})+quarantine_file({exe})[agresivo]", exito_kill and exito_cuarentena


async def _resolver_web_ip(alarma: Alarma, session: AsyncSession, grupo: str) -> tuple[str, bool]:
    """Compartido por WEB_SCAN_404, WEB_EXPLOIT_500 y SMTP_BRUTE_FORCE: solo
    cambia el piso/comportamiento según el grupo pasado."""
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
    # Piso = "moderado": nunca queda solo en notificación.
    return await _resolver_web_ip(alarma, session, ALARM_GRUPO["WEB_EXPLOIT_500"])


async def _resolver_smtp_brute_force(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    # Piso = "moderado": nunca queda solo en notificación.
    return await _resolver_web_ip(alarma, session, ALARM_GRUPO["SMTP_BRUTE_FORCE"])


async def _resolver_failed_login(alarma: Alarma, session: AsyncSession) -> tuple[str, bool]:
    detalle = alarma.detalle or {}
    usuario = detalle.get("usuario")
    ip = alarma.ip_origen
    # Piso = "moderado": nunca queda solo en notificación.
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
    pid = detalle.get("pid")  # ej. script/proceso identificado como causante del pico
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
    # Piso = "moderado": nunca queda solo en notificación.
    nivel = await obtener_nivel_efectivo(session, ALARM_GRUPO["DDOS_DETECTADO"])

    ips_validas = [ip for ip in ips if _validar_ip(ip)]
    if not ips_validas:
        return f"sin_ips_bloqueables[{nivel}]", False

    accion_fn = ip_rate_limit if nivel == "moderado" else ip_block
    resultados = [await asyncio.to_thread(accion_fn, ip) for ip in ips_validas]
    return f"{accion_fn.__name__}(x{len(resultados)})[{nivel}]", all(resultados)


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
}


async def procesar_alarmas_pendientes() -> None:
    """
    Punto de entrada del scheduler. Lee todas las alarmas con resuelta=False,
    intenta mitigarlas según su tipo_alarma, registra el resultado en
    acciones_prevencion y marca resuelta=True solo si la mitigación fue exitosa.
    """
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