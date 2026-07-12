#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/tmp_monitor.py

Módulo vii: Directorio /tmp sospechoso.
Detecta procesos activos cuyo ejecutable, directorio de trabajo (cwd) o
línea de comando referencian archivos dentro de /tmp — un patrón típico
de malware, droppers o scripts maliciosos que intentan ejecutarse desde
un directorio de escritura pública.

Complementa (no reemplaza) el control de hardening 'noexec,nosuid' en el
montaje de /tmp: ese control de prevention/secure_tmp_mount.py bloquea la
ejecución a nivel de kernel; este módulo de detección alerta si igual
aparece un proceso corriendo desde ahí (por ejemplo, si /tmp está montado
sin esas opciones, o si el binario fue copiado y ejecutado antes de que
el hardening se aplicara).

Usa el mismo contrato de 'alerts.logger' que los demás módulos de detección:

    def log_event(alarm: dict) -> bool
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
        "pip3 install --user psutil",
        file=sys.stderr,
    )
    psutil = None

# --------------------------------------------------------------------------
# Configuración
# --------------------------------------------------------------------------

MODULO_NOMBRE = "modulo_vii"
TIPO_ALARMA = "ARCHIVO_TMP_SOSPECHOSO"

LOGS_DIR_PRINCIPAL = "/var/log/hips"
LOGS_DIR_FALLBACK = os.path.join(os.getcwd(), "logs")
LOG_FILE_NAME = "tmp_monitor.log"

# Directorios considerados "de riesgo" si un proceso ejecuta o corre desde ahí
_DEFAULT_DIRS_SOSPECHOSOS = ["/tmp", "/var/tmp", "/dev/shm"]


def _cargar_dirs_sospechosos():
    dirs = list(_DEFAULT_DIRS_SOSPECHOSOS)
    raw_env = os.environ.get("MRND_TMP_DIRS", "")
    if raw_env:
        for item in raw_env.split(","):
            item = item.strip()
            if item:
                dirs.append(item)
    return dirs


DIRS_SOSPECHOSOS = _cargar_dirs_sospechosos()

# Nombres de proceso que sabemos que legítimamente corren desde /tmp o similar
# (ej: algunos gestores de paquetes o instaladores temporales conocidos)
_DEFAULT_WHITELIST = []


def _cargar_whitelist_procesos():
    procesos = list(_DEFAULT_WHITELIST)
    raw_env = os.environ.get("MRND_TMP_PROCESS_WHITELIST", "")
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

def _ruta_esta_en_dirs_sospechosos(ruta):
    """Chequea si una ruta cae dentro de alguno de los directorios sospechosos."""
    if not ruta:
        return False
    ruta_normalizada = os.path.normpath(ruta)
    for directorio in DIRS_SOSPECHOSOS:
        directorio_normalizado = os.path.normpath(directorio)
        if ruta_normalizada == directorio_normalizado or ruta_normalizada.startswith(
            directorio_normalizado + os.sep
        ):
            return True
    return False


def obtener_procesos_sospechosos():
    """
    Recorre los procesos activos y devuelve aquellos cuyo ejecutable (exe),
    directorio de trabajo (cwd) o línea de comando referencian un directorio
    sospechoso (/tmp, /var/tmp, /dev/shm). Procesos inaccesibles por permisos
    se omiten sin interrumpir el resto del recorrido.
    """
    if psutil is None:
        print("[-] No se puede monitorear /tmp sin psutil instalado.", file=sys.stderr)
        return []

    sospechosos = []
    try:
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                exe = None
                cwd = None
                cmdline = []

                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError):
                    exe = None

                try:
                    cwd = proc.cwd()
                except (psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError):
                    cwd = None

                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmdline = []

                origen_sospechoso = None
                if _ruta_esta_en_dirs_sospechosos(exe):
                    origen_sospechoso = "ejecutable"
                elif _ruta_esta_en_dirs_sospechosos(cwd):
                    origen_sospechoso = "directorio_trabajo"
                else:
                    for arg in cmdline:
                        if _ruta_esta_en_dirs_sospechosos(arg):
                            origen_sospechoso = "linea_comando"
                            break

                if origen_sospechoso:
                    info = proc.info
                    sospechosos.append({
                        "pid": info.get("pid"),
                        "nombre": info.get("name") or "desconocido",
                        "usuario": info.get("username") or "desconocido",
                        "exe": exe or "N/A",
                        "cwd": cwd or "N/A",
                        "cmdline": " ".join(cmdline) if cmdline else "N/A",
                        "origen_sospechoso": origen_sospechoso,
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                print(f"[!] Error leyendo proceso individual: {e}", file=sys.stderr)
                continue

    except Exception as e:
        print(f"[-] Error inesperado iterando procesos del sistema: {e}", file=sys.stderr)
        return []

    return sospechosos


def evaluar_proceso(proceso):
    """Decide si el proceso sospechoso debe disparar alarma (fuera de whitelist)."""
    return proceso["nombre"] not in PROCESS_WHITELIST


# --------------------------------------------------------------------------
# Construcción de la alarma
# --------------------------------------------------------------------------

def construir_alarma(proceso):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tipo_alarma": TIPO_ALARMA,
        "ip_origen": "N/A",
        "modulo": MODULO_NOMBRE,
        "resuelta": False,
        "detalle": {
            "pid": proceso["pid"],
            "nombre_proceso": proceso["nombre"],
            "usuario": proceso["usuario"],
            "exe": proceso["exe"],
            "cwd": proceso["cwd"],
            "cmdline": proceso["cmdline"],
            "origen_sospechoso": proceso["origen_sospechoso"],
        },
    }


# --------------------------------------------------------------------------
# Emisión de la alarma (mismo patrón que los demás módulos)
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

def verificar_tmp():
    """
    Ejecuta una pasada de verificación de procesos sospechosos en /tmp y
    directorios similares. Devuelve la cantidad de alarmas emitidas.
    """
    sospechosos = obtener_procesos_sospechosos()
    if not sospechosos:
        print("[.] No se detectaron procesos ejecutándose desde directorios sospechosos.")
        return 0

    alarmas_emitidas = 0
    for proceso in sospechosos:
        try:
            if evaluar_proceso(proceso):
                alarma = construir_alarma(proceso)
                if emitir_alarma(alarma):
                    alarmas_emitidas += 1
                    print(
                        f"[ALARMA] {TIPO_ALARMA} :: pid={proceso['pid']} "
                        f"proceso={proceso['nombre']} origen={proceso['origen_sospechoso']} "
                        f"exe={proceso['exe']}"
                    )
        except Exception as e:
            print(f"[-] Error procesando {proceso}: {e}", file=sys.stderr)
            continue

    return alarmas_emitidas


if __name__ == "__main__":
    try:
        total = verificar_tmp()
        print(f"[+] Verificación completada. Alarmas emitidas: {total}")
    except KeyboardInterrupt:
        print("\n[.] Verificación interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error fatal en tmp_monitor: {e}", file=sys.stderr)
        sys.exit(1)
