#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/cron_monitor.py

Módulo ix: Archivos cron.
Examina las fuentes de tareas programadas del sistema (crontab del
sistema, /etc/cron.d/, crontabs por usuario en /var/spool/cron/) y
evalúa cada entrada contra patrones de comandos/rutas sospechosas --
no compara contra un baseline (a diferencia del módulo i), porque cron
es un mecanismo que cambia legítimamente con frecuencia; el enfoque acá
es de patrón, igual que tmp_monitor.py.

Requiere privilegios de root para leer las crontabs de otros usuarios en
/var/spool/cron/.
"""

import os
import re
import sys
import glob
from datetime import datetime, timezone

NOMBRE_DETECTOR = "users_monitor"

from db_writer import obtener_conexion, insertar_alarma, insertar_evento_raw

MODULO_NOMBRE = "modulo_ix"
TIPO_ALARMA = "CRON_SOSPECHOSO"

# --------------------------------------------------------------------------
# Fuentes de tareas cron a examinar
# --------------------------------------------------------------------------

RUTA_CRONTAB_SISTEMA = "/etc/crontab"
DIRECTORIO_CRON_D = "/etc/cron.d"
DIRECTORIO_SPOOL_CRON = "/var/spool/cron"

# --------------------------------------------------------------------------
# Patrones de comandos/rutas sospechosas dentro de una tarea cron
# --------------------------------------------------------------------------

_PATRONES_SOSPECHOSOS = [
    (re.compile(r'/tmp/'), "ejecuta_desde_tmp"),
    (re.compile(r'/var/tmp/'), "ejecuta_desde_var_tmp"),
    (re.compile(r'/dev/shm/'), "ejecuta_desde_dev_shm"),
    (re.compile(r'(curl|wget)[^|]*\|\s*(ba)?sh\b'), "descarga_y_ejecuta_pipe_shell"),
    (re.compile(r'base64\s+-d'), "decodificacion_base64"),
    (re.compile(r'\b(nc|ncat|netcat)\s+.*-e\b'), "posible_shell_reversa"),
    (re.compile(r'/bin/(ba)?sh\s+-c\s+.*(curl|wget)'), "descarga_via_shell_c"),
    (re.compile(r'chmod\s+\+x\s+/tmp'), "otorga_ejecucion_en_tmp"),
]

# Comandos/rutas que sabemos que son legítimos y no deben alarmar aunque
# coincidan por casualidad con algún patrón (ej: scripts propios del HIPS
# que sí operan sobre /tmp de forma controlada).
_DEFAULT_WHITELIST_SUBSTRINGS = []


def _cargar_whitelist():
    whitelist = list(_DEFAULT_WHITELIST_SUBSTRINGS)
    raw_env = os.environ.get("MRND_CRON_WHITELIST", "")
    if raw_env:
        for item in raw_env.split(","):
            item = item.strip()
            if item:
                whitelist.append(item)
    return whitelist


WHITELIST_SUBSTRINGS = _cargar_whitelist()


# --------------------------------------------------------------------------
# Lectura de las distintas fuentes de cron
# --------------------------------------------------------------------------

def _leer_archivo_seguro(ruta):
    """Lee un archivo línea por línea. Devuelve lista vacía si falla (sin excepción)."""
    try:
        with open(ruta, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except FileNotFoundError:
        return []
    except PermissionError:
        print(f"[!] Sin permisos para leer {ruta}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[-] Error leyendo {ruta}: {e}", file=sys.stderr)
        return []


def _es_linea_relevante(linea):
    """Descarta comentarios, líneas vacías, y asignaciones de variables de entorno de cron."""
    linea = linea.strip()
    if not linea or linea.startswith("#"):
        return False
    if re.match(r'^\w+\s*=', linea):  # ej: PATH=/usr/bin, SHELL=/bin/bash
        return False
    return True


def obtener_todas_las_tareas_cron():
    """
    Recolecta todas las tareas cron de todas las fuentes del sistema.
    Devuelve una lista de dicts: {fuente, linea_raw, comando}.
    """
    tareas = []

    for linea in _leer_archivo_seguro(RUTA_CRONTAB_SISTEMA):
        if _es_linea_relevante(linea):
            tareas.append({
                "fuente": RUTA_CRONTAB_SISTEMA,
                "linea_raw": linea.strip(),
                "comando": linea.strip(),
            })

    try:
        archivos_cron_d = glob.glob(os.path.join(DIRECTORIO_CRON_D, "*"))
    except Exception as e:
        print(f"[-] Error listando {DIRECTORIO_CRON_D}: {e}", file=sys.stderr)
        archivos_cron_d = []

    for ruta_archivo in archivos_cron_d:
        if not os.path.isfile(ruta_archivo):
            continue
        for linea in _leer_archivo_seguro(ruta_archivo):
            if _es_linea_relevante(linea):
                tareas.append({
                    "fuente": ruta_archivo,
                    "linea_raw": linea.strip(),
                    "comando": linea.strip(),
                })

    try:
        archivos_spool = glob.glob(os.path.join(DIRECTORIO_SPOOL_CRON, "*"))
    except Exception as e:
        print(f"[-] Error listando {DIRECTORIO_SPOOL_CRON}: {e}", file=sys.stderr)
        archivos_spool = []

    for ruta_archivo in archivos_spool:
        if not os.path.isfile(ruta_archivo):
            continue
        usuario_propietario = os.path.basename(ruta_archivo)
        for linea in _leer_archivo_seguro(ruta_archivo):
            if _es_linea_relevante(linea):
                tareas.append({
                    "fuente": f"crontab_usuario:{usuario_propietario}",
                    "linea_raw": linea.strip(),
                    "comando": linea.strip(),
                })

    return tareas


# --------------------------------------------------------------------------
# Evaluación de cada tarea
# --------------------------------------------------------------------------

def _esta_en_whitelist(comando):
    return any(sub in comando for sub in WHITELIST_SUBSTRINGS)


def evaluar_tarea(tarea):
    """
    Evalúa una tarea cron contra los patrones sospechosos. Devuelve una
    lista de motivos que matchearon (vacía si no hay ninguno).
    """
    if _esta_en_whitelist(tarea["comando"]):
        return []

    motivos = []
    for patron, nombre_motivo in _PATRONES_SOSPECHOSOS:
        if patron.search(tarea["comando"]):
            motivos.append(nombre_motivo)

    return motivos


# --------------------------------------------------------------------------
# Punto de entrada del módulo
# --------------------------------------------------------------------------

def verificar_cron():
    """
    Ejecuta una pasada de verificación de todas las tareas cron del
    sistema. Devuelve la cantidad de alarmas emitidas.
    """
    conexion_db = obtener_conexion()
    timestamp = datetime.now(timezone.utc)

    tareas = obtener_todas_las_tareas_cron()
    if not tareas:
        print("[.] No se encontraron tareas cron para examinar (o no hay permisos suficientes).")
        if conexion_db is not None:
            conexion_db.close()
        return 0

    alarmas_emitidas = 0
    for tarea in tareas:
        try:
            insertar_evento_raw(
                conexion_db,
                timestamp=timestamp,
                fuente=tarea["fuente"],
                ip_origen=None,
                usuario=None,
                contenido_raw=tarea["linea_raw"],
                modulo=MODULO_NOMBRE,
            )
        except Exception as e:
            print(f"[!] Error normalizando tarea cron a eventos_raw: {e}", file=sys.stderr)

        try:
            motivos = evaluar_tarea(tarea)
            if motivos:
                detalle = {
                    "fuente": tarea["fuente"],
                    "comando": tarea["comando"],
                    "motivos": motivos,
                }
                insertar_alarma(
                    conexion_db,
                    timestamp=timestamp,
                    tipo_alarma=TIPO_ALARMA,
                    ip_origen="N/A",
                    modulo=MODULO_NOMBRE,
                    detalle=detalle,
                )
                print(f"[ALARMA] {TIPO_ALARMA} :: fuente={tarea['fuente']} "
                      f"motivos={motivos} comando={tarea['comando']}")
                alarmas_emitidas += 1
        except Exception as e:
            print(f"[-] Error evaluando tarea cron {tarea}: {e}", file=sys.stderr)

    print(f"[.] Tareas cron examinadas: {len(tareas)}")

    if conexion_db is not None:
        conexion_db.close()

    return alarmas_emitidas


if __name__ == "__main__":
    try:
        total = verificar_cron()
        print(f"[+] Verificación completada. Alarmas emitidas: {total}")
    except KeyboardInterrupt:
        print("\n[.] Verificación interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error fatal en cron_monitor: {e}", file=sys.stderr)
        sys.exit(1)
