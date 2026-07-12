#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/users_monitor.py

Módulo ii: Usuarios conectados.
Monitorea las sesiones activas del sistema (who / last) y genera una alarma
cuando detecta un usuario o un origen de conexión no reconocido/no confiable.

Contrato esperado de 'alerts.logger' (aún no implementado por el compañero de
equipo en la rama 'julian'):

    def log_event(alarm: dict) -> bool

Hasta que ese módulo exista, este archivo usa un fallback local que escribe en
/var/log/hips/ (o en ./logs/ si no hay privilegios de root, típico en pruebas
locales sobre la VM de ZeroTier).
"""

import os
import re
import sys
import json
import subprocess
import ipaddress
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Configuración (prefijo MRND_ según convención de variables de entorno)
# --------------------------------------------------------------------------

MODULO_NOMBRE = "modulo_ii"
TIPO_ALARMA = "USUARIO_SOSPECHOSO"

# Directorio mandatorio de logs (definido también en prevention/rsyslog_centralization.py)
LOGS_DIR_PRINCIPAL = "/var/log/hips"
LOGS_DIR_FALLBACK = os.path.join(os.getcwd(), "logs")
LOG_FILE_NAME = "users_monitor.log"

# IPs/orígenes que NO deben disparar alarma (ej: tu propia IP de ZeroTier
# mientras probás por SSH, o la IP de tu compañero).
# Se puede sobreescribir con la variable de entorno MRND_TRUSTED_IPS
# separando valores por coma, ej: "10.186.164.108,10.186.0.0/16"
_DEFAULT_TRUSTED = ["127.0.0.1", "::1"]


def _cargar_ips_confiables():
    """Lee MRND_TRUSTED_IPS del entorno y arma la lista final de redes/IPs confiables."""
    confiables = list(_DEFAULT_TRUSTED)
    raw_env = os.environ.get("MRND_TRUSTED_IPS", "")
    if raw_env:
        for item in raw_env.split(","):
            item = item.strip()
            if item:
                confiables.append(item)
    return confiables


TRUSTED_SOURCES = _cargar_ips_confiables()

# Usuarios de sistema que jamás deben considerarse "sospechosos" por sí solos
USUARIOS_BASELINE = set(
    filter(None, os.environ.get("MRND_BASELINE_USERS", "root").split(","))
)


# --------------------------------------------------------------------------
# Utilidades de ejecución de comandos (con manejo de errores extremo)
# --------------------------------------------------------------------------

def ejecutar_comando(comando, timeout=5):
    """
    Ejecuta un comando del sistema de forma segura.
    Devuelve (True, stdout) en éxito o (False, mensaje_error) en fallo.
    Nunca lanza una excepción hacia el llamador.
    """
    try:
        resultado = subprocess.run(
            comando,
            shell=False,
            check=True,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return True, resultado.stdout
    except FileNotFoundError:
        return False, f"Comando no encontrado: {comando[0]}"
    except subprocess.TimeoutExpired:
        return False, f"Timeout ejecutando: {' '.join(comando)}"
    except subprocess.CalledProcessError as e:
        return False, f"Error de ejecución ({e.returncode}): {e.stderr.strip() if e.stderr else 'sin detalle'}"
    except Exception as e:  # Resiliencia extrema: nunca debe morir el módulo por esto
        return False, f"Error inesperado ejecutando comando: {e}"


# --------------------------------------------------------------------------
# Parseo de sesiones activas
# --------------------------------------------------------------------------

# Ejemplo típico de línea 'who':
# dan      pts/0        2026-07-12 14:03 (10.186.164.1)
_PATRON_WHO = re.compile(
    r"^(?P<usuario>\S+)\s+(?P<tty>\S+)\s+(?P<fecha>\d{4}-\d{2}-\d{2})\s+(?P<hora>\d{2}:\d{2})"
    r"(?:\s+\((?P<origen>[^)]+)\))?"
)


def obtener_sesiones_activas():
    """
    Obtiene la lista de sesiones activas parseando la salida de 'who'.
    Devuelve una lista de dicts: {usuario, tty, timestamp, origen_ip}
    En caso de error de ejecución, devuelve lista vacía (falla segura, no falla ruidosa).
    """
    ok, salida = ejecutar_comando(["who"])
    if not ok:
        print(f"[-] No se pudo obtener sesiones activas: {salida}", file=sys.stderr)
        return []

    sesiones = []
    for linea in salida.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        match = _PATRON_WHO.match(linea)
        if not match:
            # Línea con formato inesperado: la registramos para diagnóstico,
            # pero no interrumpimos el procesamiento del resto.
            print(f"[!] Línea de 'who' no reconocida, se omite: {linea}", file=sys.stderr)
            continue

        datos = match.groupdict()
        origen = datos.get("origen") or "local"

        sesiones.append({
            "usuario": datos["usuario"],
            "tty": datos["tty"],
            "timestamp": f"{datos['fecha']} {datos['hora']}",
            "origen_ip": origen,
        })

    return sesiones


# --------------------------------------------------------------------------
# Evaluación de confiabilidad del origen
# --------------------------------------------------------------------------

def origen_es_confiable(origen):
    """
    Determina si un origen (IP o 'local') está dentro de la lista de fuentes
    confiables. Maneja tanto IPs sueltas como rangos CIDR en TRUSTED_SOURCES.
    """
    if origen == "local":
        return True

    try:
        ip_origen = ipaddress.ip_address(origen)
    except ValueError:
        # Si 'who' devolvió un hostname en vez de IP, no podemos validarlo
        # como confiable: lo tratamos como no confiable por precaución.
        return False

    for fuente in TRUSTED_SOURCES:
        try:
            if "/" in fuente:
                if ip_origen in ipaddress.ip_network(fuente, strict=False):
                    return True
            else:
                if ip_origen == ipaddress.ip_address(fuente):
                    return True
        except ValueError:
            # Entrada mal configurada en MRND_TRUSTED_IPS: la ignoramos
            # sin romper la evaluación de las demás.
            print(f"[!] Entrada inválida en MRND_TRUSTED_IPS ignorada: {fuente}", file=sys.stderr)
            continue

    return False


def evaluar_sesion(sesion):
    """
    Decide si una sesión activa debe disparar alarma.
    Regla: se alarma si el origen NO es confiable, sin importar el usuario
    (un usuario legítimo desde una IP desconocida también es sospechoso).
    """
    return not origen_es_confiable(sesion["origen_ip"])


# --------------------------------------------------------------------------
# Construcción de la alarma (mapea a columnas de la tabla 'alarmas')
# --------------------------------------------------------------------------

def construir_alarma(sesion):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tipo_alarma": TIPO_ALARMA,
        "ip_origen": sesion["origen_ip"],
        "modulo": MODULO_NOMBRE,
        "resuelta": False,
        "detalle": {
            "usuario": sesion["usuario"],
            "tty": sesion["tty"],
            "login_reportado": sesion["timestamp"],
        },
    }


# --------------------------------------------------------------------------
# Emisión de la alarma: intenta usar el logger central de Julián;
# si todavía no existe, usa un fallback local para no bloquear tu desarrollo.
# --------------------------------------------------------------------------

def _resolver_directorio_logs():
    """Elige el directorio de logs mandatorio si es escribible, o el fallback local."""
    try:
        os.makedirs(LOGS_DIR_PRINCIPAL, mode=0o750, exist_ok=True)
        if os.access(LOGS_DIR_PRINCIPAL, os.W_OK):
            return LOGS_DIR_PRINCIPAL
    except PermissionError:
        pass
    except Exception as e:
        print(f"[!] No se pudo preparar {LOGS_DIR_PRINCIPAL}: {e}", file=sys.stderr)

    try:
        os.makedirs(LOGS_DIR_FALLBACK, exist_ok=True)
    except Exception as e:
        print(f"[-] No se pudo crear directorio de logs de fallback: {e}", file=sys.stderr)
        return None

    return LOGS_DIR_FALLBACK


def _emitir_alarma_fallback(alarma):
    """Escribe la alarma en formato JSON-line mientras alerts/logger.py no exista."""
    directorio = _resolver_directorio_logs()
    if directorio is None:
        print(f"[-] ALARMA NO PERSISTIDA (sin directorio de logs disponible): {alarma}", file=sys.stderr)
        return False

    ruta_log = os.path.join(directorio, LOG_FILE_NAME)
    try:
        with open(ruta_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(alarma, ensure_ascii=False) + "\n")
        return True
    except (IOError, OSError) as e:
        print(f"[-] Error escribiendo alarma en {ruta_log}: {e}", file=sys.stderr)
        return False


def emitir_alarma(alarma):
    """
    Punto único de emisión de alarmas para este módulo.
    Intenta delegar en alerts.logger.log_event (de Julián); si ese módulo
    todavía no expone la función, cae al fallback local sin romper ejecución.
    """
    try:
        from alerts.logger import log_event  # type: ignore
        return log_event(alarma)
    except ImportError:
        return _emitir_alarma_fallback(alarma)
    except AttributeError:
        print("[!] alerts.logger existe pero no define log_event(); usando fallback.", file=sys.stderr)
        return _emitir_alarma_fallback(alarma)
    except Exception as e:
        print(f"[-] Error inesperado delegando en alerts.logger: {e}", file=sys.stderr)
        return _emitir_alarma_fallback(alarma)


# --------------------------------------------------------------------------
# Punto de entrada del módulo
# --------------------------------------------------------------------------

def verificar_usuarios_conectados():
    """
    Ejecuta una pasada de verificación: obtiene sesiones activas, evalúa cada
    una y emite alarma para las sospechosas. Devuelve la cantidad de alarmas emitidas.
    """
    sesiones = obtener_sesiones_activas()
    if not sesiones:
        print("[.] No hay sesiones activas o no se pudieron leer.")
        return 0

    alarmas_emitidas = 0
    for sesion in sesiones:
        try:
            if evaluar_sesion(sesion):
                alarma = construir_alarma(sesion)
                if emitir_alarma(alarma):
                    alarmas_emitidas += 1
                    print(f"[ALARMA] {TIPO_ALARMA} :: usuario={sesion['usuario']} :: origen={sesion['origen_ip']}")
        except Exception as e:
            # Ninguna sesión individual debe tumbar el procesamiento de las demás.
            print(f"[-] Error procesando sesión {sesion}: {e}", file=sys.stderr)
            continue

    return alarmas_emitidas


if __name__ == "__main__":
    try:
        total = verificar_usuarios_conectados()
        print(f"[+] Verificación completada. Alarmas emitidas: {total}")
    except KeyboardInterrupt:
        print("\n[.] Verificación interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error fatal en users_monitor: {e}", file=sys.stderr)
        sys.exit(1)