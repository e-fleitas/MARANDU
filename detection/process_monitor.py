#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/process_monitor.py

Módulo vi: Procesos con alto consumo de recursos (CPU / RAM).
Recorre los procesos activos del sistema con psutil y genera una alarma
cuando alguno supera los umbrales configurados de uso de CPU o memoria,
salvo que esté en la lista de procesos conocidos/permitidos.

Usa el mismo contrato de 'alerts.logger' que detection/users_monitor.py:

    def log_event(alarm: dict) -> bool

Mientras ese módulo no exista en 'alerts/logger.py', cae al mismo fallback
local (JSON-lines en /var/log/hips/ o ./logs/).
"""

import os
import sys
import json
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    print(
        "[-] La librería 'psutil' no está instalada. Instalala con: "
        "pip install psutil (o revisá requirements.txt).",
        file=sys.stderr,
    )
    psutil = None

# --------------------------------------------------------------------------
# Configuración (prefijo MRND_ según convención de variables de entorno)
# --------------------------------------------------------------------------

MODULO_NOMBRE = "modulo_vi"
TIPO_ALARMA = "PROCESO_ALTO_CONSUMO"

LOGS_DIR_PRINCIPAL = "/var/log/hips"
LOGS_DIR_FALLBACK = os.path.join(os.getcwd(), "logs")
LOG_FILE_NAME = "process_monitor.log"

# Umbrales configurables por entorno
CPU_THRESHOLD = float(os.environ.get("MRND_CPU_THRESHOLD", "85"))       # % de CPU
MEM_THRESHOLD = float(os.environ.get("MRND_MEM_THRESHOLD", "80"))       # % de RAM

# Procesos que NUNCA deben alarmar aunque consuman recursos altos
# (ej: el propio postgres, el intérprete de python corriendo el HIPS, etc.)
_DEFAULT_WHITELIST = ["postgres", "postmaster", "python3", "systemd"]


def _cargar_whitelist_procesos():
    procesos = list(_DEFAULT_WHITELIST)
    raw_env = os.environ.get("MRND_PROCESS_WHITELIST", "")
    if raw_env:
        for item in raw_env.split(","):
            item = item.strip()
            if item:
                procesos.append(item)
    return set(procesos)


PROCESS_WHITELIST = _cargar_whitelist_procesos()


# --------------------------------------------------------------------------
# Obtención y evaluación de procesos
# --------------------------------------------------------------------------

def obtener_procesos():
    """
    Devuelve una lista de dicts {pid, nombre, usuario, cpu_percent, mem_percent}
    para todos los procesos accesibles. Nunca lanza excepción hacia el llamador:
    procesos individuales inaccesibles (permisos, ya finalizados) se omiten.
    """
    if psutil is None:
        print("[-] No se puede monitorear procesos sin psutil instalado.", file=sys.stderr)
        return []

    procesos = []
    try:
        # Primera pasada para "calentar" el cálculo de cpu_percent (requiere
        # un intervalo de referencia; sin esto, el primer valor siempre es 0.0)
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        import time
        time.sleep(0.5)  # intervalo mínimo para obtener una lectura real de CPU

        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                info = proc.info
                cpu = proc.cpu_percent(interval=None)
                mem = proc.memory_percent()
                procesos.append({
                    "pid": info.get("pid"),
                    "nombre": info.get("name") or "desconocido",
                    "usuario": info.get("username") or "desconocido",
                    "cpu_percent": cpu,
                    "mem_percent": round(mem, 2),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # El proceso murió o no tenemos permiso: lo salteamos sin ruido.
                continue
            except Exception as e:
                print(f"[!] Error leyendo proceso individual: {e}", file=sys.stderr)
                continue

    except Exception as e:
        print(f"[-] Error inesperado iterando procesos del sistema: {e}", file=sys.stderr)
        return []

    return procesos


def evaluar_proceso(proceso):
    """
    Decide si un proceso debe disparar alarma: supera CPU o memoria por encima
    del umbral, y su nombre no está en la whitelist.
    """
    if proceso["nombre"] in PROCESS_WHITELIST:
        return False, None

    if proceso["cpu_percent"] >= CPU_THRESHOLD:
        return True, "cpu"
    if proceso["mem_percent"] >= MEM_THRESHOLD:
        return True, "memoria"

    return False, None


# --------------------------------------------------------------------------
# Construcción de la alarma
# --------------------------------------------------------------------------

def construir_alarma(proceso, motivo):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tipo_alarma": TIPO_ALARMA,
        "ip_origen": "N/A",  # este módulo es local al host, sin origen de red
        "modulo": MODULO_NOMBRE,
        "resuelta": False,
        "detalle": {
            "pid": proceso["pid"],
            "nombre_proceso": proceso["nombre"],
            "usuario": proceso["usuario"],
            "cpu_percent": proceso["cpu_percent"],
            "mem_percent": proceso["mem_percent"],
            "motivo": motivo,
        },
    }


# --------------------------------------------------------------------------
# Emisión de la alarma (idéntico patrón a users_monitor.py)
# --------------------------------------------------------------------------

def _resolver_directorio_logs():
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

def verificar_procesos():
    """
    Ejecuta una pasada de verificación de procesos. Devuelve la cantidad de
    alarmas emitidas.
    """
    procesos = obtener_procesos()
    if not procesos:
        print("[.] No se pudo leer la lista de procesos o está vacía.")
        return 0

    alarmas_emitidas = 0
    for proceso in procesos:
        try:
            dispara, motivo = evaluar_proceso(proceso)
            if dispara:
                alarma = construir_alarma(proceso, motivo)
                if emitir_alarma(alarma):
                    alarmas_emitidas += 1
                    print(
                        f"[ALARMA] {TIPO_ALARMA} :: pid={proceso['pid']} "
                        f"proceso={proceso['nombre']} motivo={motivo} "
                        f"cpu={proceso['cpu_percent']}% mem={proceso['mem_percent']}%"
                    )
        except Exception as e:
            print(f"[-] Error procesando {proceso}: {e}", file=sys.stderr)
            continue

    return alarmas_emitidas


if __name__ == "__main__":
    try:
        total = verificar_procesos()
        print(f"[+] Verificación completada. Alarmas emitidas: {total}")
    except KeyboardInterrupt:
        print("\n[.] Verificación interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error fatal en process_monitor: {e}", file=sys.stderr)
        sys.exit(1)