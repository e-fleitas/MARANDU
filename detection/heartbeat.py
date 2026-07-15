#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/heartbeat.py

Utilidad compartida de "latido" de detectores. Cada script de detection/
llama a marcar_heartbeat(nombre) al terminar una pasada (exitosa o no),
dejando constancia de cuándo corrió por última vez. El dashboard web lee
ese registro (vía leer_heartbeats) para decidir si un detector sigue
corriendo con normalidad -- si cron lo dispara cada 2 minutos y no hay
heartbeat reciente, algo se rompió -- y así pintar el puntito verde/rojo
al lado de cada tipo de alarma en la tabla "Alarmas & Respuesta".

No depende de la base de datos a propósito: si Postgres está caído o
credenciales mal configuradas, igual queremos saber si el detector en sí
sigue vivo, así que esto vive en un archivo JSON plano protegido con
flock (mismo patrón de resolución de directorio que users_monitor.py:
directorio mandatorio si es escribible, si no, fallback local).
"""

import os
import sys
import json
import fcntl
import datetime

HEARTBEAT_DIR_PRINCIPAL = "/var/lib/hips"
HEARTBEAT_DIR_FALLBACK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
HEARTBEAT_FILE_NAME = "detector_heartbeats.json"


def _resolver_ruta_heartbeat():
    """Elige el archivo de heartbeats en el directorio mandatorio si es
    escribible, o el fallback local. Mismo criterio que
    users_monitor.py._resolver_directorio_logs()."""
    try:
        os.makedirs(HEARTBEAT_DIR_PRINCIPAL, mode=0o755, exist_ok=True)
        if os.access(HEARTBEAT_DIR_PRINCIPAL, os.W_OK):
            return os.path.join(HEARTBEAT_DIR_PRINCIPAL, HEARTBEAT_FILE_NAME)
    except PermissionError:
        pass
    except Exception as e:
        print(f"[!] No se pudo preparar {HEARTBEAT_DIR_PRINCIPAL}: {e}", file=sys.stderr)

    try:
        os.makedirs(HEARTBEAT_DIR_FALLBACK, exist_ok=True)
        return os.path.join(HEARTBEAT_DIR_FALLBACK, HEARTBEAT_FILE_NAME)
    except Exception as e:
        print(f"[-] No se pudo crear directorio de heartbeats de fallback: {e}", file=sys.stderr)
        return None


def marcar_heartbeat(nombre_detector: str, alarmas_emitidas: int = 0, ok: bool = True) -> bool:
    """
    Registra que 'nombre_detector' completó una pasada. Se llama una vez,
    al final del bloque `if __name__ == "__main__":` de cada detector,
    idealmente tanto en el camino exitoso como en el except (con ok=False)
    para poder distinguir "no corrió" de "corrió y falló".

    nombre_detector: id estable y legible, ej. "users_monitor",
    "ddos_detector" -- usar el nombre del archivo sin ".py" para que
    coincida con GRUPO_A_DETECTOR en web/app.py.
    """
    ruta = _resolver_ruta_heartbeat()
    if ruta is None:
        return False

    registro = {
        "ultima_ejecucion": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "alarmas_emitidas": alarmas_emitidas,
        "ok": ok,
    }

    try:
        # Abrimos en "a+" para poder tomar el lock aunque el archivo no
        # exista todavía, y después reescribimos el JSON completo -- son
        # pocos detectores (~10) corriendo cada 2 minutos, así que
        # reescribir el archivo entero por heartbeat no es un problema de
        # performance, y evita tener que mergear líneas sueltas.
        with open(ruta, "a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                contenido = f.read()
                try:
                    datos = json.loads(contenido) if contenido.strip() else {}
                except json.JSONDecodeError:
                    datos = {}
                datos[nombre_detector] = registro
                f.seek(0)
                f.truncate()
                f.write(json.dumps(datos, ensure_ascii=False, indent=2))
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return True
    except (IOError, OSError) as e:
        print(f"[-] Error registrando heartbeat de {nombre_detector}: {e}", file=sys.stderr)
        return False


def leer_heartbeats() -> dict:
    """Devuelve {detector: {ultima_ejecucion, alarmas_emitidas, ok}} o {}
    si todavía no corrió ningún detector. Usado por web/app.py (proceso
    'marandu' sin privilegios) -- por eso solo lee, nunca escribe acá."""
    ruta = _resolver_ruta_heartbeat()
    if ruta is None or not os.path.exists(ruta):
        return {}
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                contenido = f.read()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return json.loads(contenido) if contenido.strip() else {}
    except (IOError, OSError, json.JSONDecodeError):
        return {}