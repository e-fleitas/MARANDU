#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/file_integrity_monitor.py

Módulo i: Integridad de archivos del sistema.
Verifica que /etc/passwd y /etc/shadow no hayan sido modificados,
comparando su hash SHA-256 actual contra un baseline guardado de forma
segura -- en este caso, en la tabla `configuracion_modulos` de PostgreSQL
(cumple el requisito 4.3 del TP: almacenamiento seguro de configuración
en base de datos, en vez de un archivo plano en el mismo disco que podría
ser alterado junto con el archivo vigilado).

Requiere privilegios de root para leer /etc/shadow (permisos 600/000,
solo root). Correr con sudo, o vía systemd service con capabilities
adecuadas.

Modo de uso:
  python3 file_integrity_monitor.py --init      -> graba el baseline actual
  python3 file_integrity_monitor.py             -> verifica contra el baseline
"""

import os
import sys
import hashlib
from datetime import datetime, timezone

from db_writer import obtener_conexion, insertar_alarma, insertar_evento_raw

MODULO_NOMBRE = "modulo_i"
TIPO_ALARMA_PASSWD = "MODIFICACION_PASSWD"
TIPO_ALARMA_SHADOW = "MODIFICACION_SHADOW"

ARCHIVOS_VIGILADOS = {
    "/etc/passwd": TIPO_ALARMA_PASSWD,
    "/etc/shadow": TIPO_ALARMA_SHADOW,
}


def calcular_hash(ruta_archivo):
    """
    Calcula el hash SHA-256 de un archivo. Devuelve (True, hash_hex) en
    éxito, o (False, mensaje_error) en fallo. Nunca lanza excepción hacia
    el llamador.
    """
    try:
        hasher = hashlib.sha256()
        with open(ruta_archivo, "rb") as f:
            for bloque in iter(lambda: f.read(65536), b""):
                hasher.update(bloque)
        return True, hasher.hexdigest()
    except FileNotFoundError:
        return False, f"Archivo no encontrado: {ruta_archivo}"
    except PermissionError:
        return False, f"Sin permisos para leer {ruta_archivo} (¿corriste con sudo?)"
    except Exception as e:
        return False, f"Error inesperado calculando hash de {ruta_archivo}: {e}"


def obtener_baseline(conexion_db, ruta_archivo):
    """
    Lee el hash baseline guardado para un archivo desde
    configuracion_modulos. Devuelve el hash (str) o None si no existe
    todavía (primera vez que corre el módulo).
    """
    if conexion_db is None:
        return None

    parametro = f"baseline_sha256_{ruta_archivo}"
    query = """
        SELECT valor FROM configuracion_modulos
        WHERE modulo = %s AND parametro = %s
        ORDER BY id DESC LIMIT 1;
    """
    try:
        with conexion_db.cursor() as cur:
            cur.execute(query, (MODULO_NOMBRE, parametro))
            fila = cur.fetchone()
            return fila[0] if fila else None
    except Exception as e:
        print(f"[-] Error leyendo baseline de {ruta_archivo}: {e}", file=sys.stderr)
        return None


def guardar_baseline(conexion_db, ruta_archivo, hash_valor):
    """
    Guarda (o actualiza) el hash baseline para un archivo en
    configuracion_modulos. Devuelve True en éxito, False en fallo.
    """
    if conexion_db is None:
        return False

    parametro = f"baseline_sha256_{ruta_archivo}"
    query_delete = """
        DELETE FROM configuracion_modulos WHERE modulo = %s AND parametro = %s;
    """
    query_insert = """
        INSERT INTO configuracion_modulos (modulo, parametro, valor, activo)
        VALUES (%s, %s, %s, %s);
    """
    try:
        with conexion_db.cursor() as cur:
            cur.execute(query_delete, (MODULO_NOMBRE, parametro))
            cur.execute(query_insert, (MODULO_NOMBRE, parametro, hash_valor, True))
        return True
    except Exception as e:
        print(f"[-] Error guardando baseline de {ruta_archivo}: {e}", file=sys.stderr)
        return False


def inicializar_baseline():
    """
    Calcula y guarda el hash actual de cada archivo vigilado como el
    baseline "conocido bueno". Se corre una sola vez, en un momento en que
    el sistema está en un estado confiable (recién configurado, sin
    intrusiones conocidas).
    """
    conexion_db = obtener_conexion()
    if conexion_db is None:
        print("[-] No se pudo conectar a la base de datos. No se puede inicializar el baseline.", file=sys.stderr)
        return False

    exito_total = True
    for ruta_archivo in ARCHIVOS_VIGILADOS:
        ok, resultado = calcular_hash(ruta_archivo)
        if not ok:
            print(f"[-] {resultado}", file=sys.stderr)
            exito_total = False
            continue

        if guardar_baseline(conexion_db, ruta_archivo, resultado):
            print(f"[+] Baseline guardado para {ruta_archivo}: {resultado[:16]}...")
        else:
            exito_total = False

    conexion_db.close()
    return exito_total


def verificar_integridad():
    """
    Compara el hash actual de cada archivo vigilado contra su baseline.
    Dispara alarma si difieren, o si no hay baseline todavía (primera
    corrida sin --init, o el archivo es nuevo). Devuelve la cantidad de
    alarmas emitidas.
    """
    conexion_db = obtener_conexion()
    alarmas_emitidas = 0
    timestamp = datetime.now(timezone.utc)

    for ruta_archivo, tipo_alarma in ARCHIVOS_VIGILADOS.items():
        ok, hash_actual = calcular_hash(ruta_archivo)
        if not ok:
            print(f"[-] {hash_actual}", file=sys.stderr)
            continue

        try:
            insertar_evento_raw(
                conexion_db,
                timestamp=timestamp,
                fuente="file_integrity",
                ip_origen=None,
                usuario=None,
                contenido_raw=f"archivo={ruta_archivo} hash_sha256={hash_actual}",
                modulo=MODULO_NOMBRE,
            )
        except Exception as e:
            print(f"[!] Error normalizando evento de integridad a eventos_raw: {e}", file=sys.stderr)

        hash_baseline = obtener_baseline(conexion_db, ruta_archivo)

        if hash_baseline is None:
            print(f"[!] No hay baseline guardado para {ruta_archivo}. "
                  f"Corré con --init primero para establecer uno.", file=sys.stderr)
            continue

        if hash_actual != hash_baseline:
            detalle = {
                "archivo": ruta_archivo,
                "hash_baseline": hash_baseline,
                "hash_actual": hash_actual,
            }
            try:
                insertar_alarma(
                    conexion_db,
                    timestamp=timestamp,
                    tipo_alarma=tipo_alarma,
                    ip_origen="N/A",
                    modulo=MODULO_NOMBRE,
                    detalle=detalle,
                )
                print(f"[ALARMA] {tipo_alarma} :: archivo={ruta_archivo} "
                      f"(hash cambió de {hash_baseline[:16]}... a {hash_actual[:16]}...)")
                alarmas_emitidas += 1
            except Exception as e:
                print(f"[-] Error insertando alarma de integridad: {e}", file=sys.stderr)
        else:
            print(f"[.] {ruta_archivo}: integridad OK (hash sin cambios)")

    if conexion_db is not None:
        conexion_db.close()

    return alarmas_emitidas


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Este módulo necesita privilegios de root para leer /etc/shadow. "
              "Corré con: sudo python3 detection/file_integrity_monitor.py", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        exito = inicializar_baseline()
        sys.exit(0 if exito else 1)
    else:
        try:
            total = verificar_integridad()
            print(f"[+] Verificación completada. Alarmas emitidas: {total}")
        except KeyboardInterrupt:
            print("\n[.] Verificación interrumpida por el usuario.")
            sys.exit(0)
        except Exception as e:
            print(f"[-] Error fatal en file_integrity_monitor: {e}", file=sys.stderr)
            sys.exit(1)
