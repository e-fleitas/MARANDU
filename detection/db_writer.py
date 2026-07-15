#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/db_writer.py

Utilidad compartida para que los scripts de detección (que corren como
procesos standalone, no como parte de la app FastAPI) escriban a PostgreSQL
de forma síncrona con psycopg2 -- independiente del event loop async que usa
web/app.py con asyncpg.

Lee la conexión desde el DATABASE_URL del .env del proyecto, convirtiendo el
driver de 'postgresql+asyncpg' a 'postgresql' (sync) automáticamente.
"""

import os
import sys
import json

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print(
        "[-] La librería 'psycopg2-binary' no está instalada. Instalala con: "
        "pip3 install --user psycopg2-binary",
        file=sys.stderr,
    )
    psycopg2 = None

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


def _ruta_env():
    """Ubica el .env en la raíz del proyecto, sin importar desde dónde se ejecute el script."""
    return os.path.join(os.path.dirname(__file__), "..", ".env")


def _cargar_database_url():
    """
    Lee DATABASE_URL del .env del proyecto y lo convierte al driver síncrono
    (psycopg2) si viene configurado para el driver async (asyncpg).
    """
    if load_dotenv is not None:
        load_dotenv(_ruta_env())

    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "Falta DATABASE_URL en el .env del proyecto. "
            "Revisá que exista la línea DATABASE_URL=postgresql+asyncpg://... en .env"
        )

    # psycopg2 no entiende el sufijo +asyncpg; lo convertimos al driver síncrono.
    if "+asyncpg" in url:
        url = url.replace("postgresql+asyncpg", "postgresql")

    return url


def obtener_conexion():
    """
    Abre una conexión síncrona a PostgreSQL. Devuelve None si falla (nunca
    lanza excepción hacia el llamador), para que los módulos de detección
    puedan seguir funcionando con su fallback local si la DB no está disponible.
    """
    if psycopg2 is None:
        return None

    try:
        url = _cargar_database_url()
    except RuntimeError as e:
        print(f"[-] {e}", file=sys.stderr)
        return None

    try:
        conexion = psycopg2.connect(url, connect_timeout=5)
        conexion.autocommit = True
        return conexion
    except psycopg2.OperationalError as e:
        print(f"[-] No se pudo conectar a la base de datos: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[-] Error inesperado conectando a la base de datos: {e}", file=sys.stderr)
        return None


def insertar_alarma(conexion, timestamp, tipo_alarma, ip_origen, modulo, detalle=None):
    """
    Inserta una fila en la tabla 'alarmas'. Devuelve el id generado, o None
    si falla (la llamada nunca lanza excepción hacia el módulo de detección).
    """
    if conexion is None:
        return None

    query = """
        INSERT INTO alarmas (timestamp, tipo_alarma, ip_origen, modulo, resuelta, detalle)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id;
    """
    detalle_json = json.dumps(detalle, ensure_ascii=False) if detalle is not None else None

    try:
        with conexion.cursor() as cur:
            cur.execute(query, (timestamp, tipo_alarma, ip_origen, modulo, False, detalle_json))
            fila = cur.fetchone()
            return fila[0] if fila else None
    except psycopg2.Error as e:
        print(f"[-] Error insertando alarma en la base de datos: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[-] Error inesperado insertando alarma: {e}", file=sys.stderr)
        return None


def insertar_evento_raw(conexion, timestamp, fuente, ip_origen, usuario, contenido_raw, modulo):
    """
    Inserta una fila en la tabla 'eventos_raw'. Devuelve el id generado, o
    None si falla.
    """
    if conexion is None:
        return None

    query = """
        INSERT INTO eventos_raw (timestamp, fuente, ip_origen, usuario, contenido_raw, modulo, procesado)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    """
    try:
        with conexion.cursor() as cur:
            cur.execute(query, (timestamp, fuente, ip_origen, usuario, contenido_raw, modulo, False))
            fila = cur.fetchone()
            return fila[0] if fila else None
    except psycopg2.Error as e:
        print(f"[-] Error insertando evento_raw en la base de datos: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[-] Error inesperado insertando evento_raw: {e}", file=sys.stderr)
        return None


if __name__ == "__main__":
    # Prueba manual rápida: conecta e inserta un evento_raw + una alarma de prueba.
    import datetime

    conn = obtener_conexion()
    if conn is None:
        print("[-] No se pudo conectar. Revisá DATABASE_URL en .env.", file=sys.stderr)
        sys.exit(1)

    print("[+] Conexión exitosa a la base de datos.")

    evento_id = insertar_evento_raw(
        conn,
        timestamp=datetime.datetime.now(datetime.UTC),
        fuente="prueba_manual",
        ip_origen="127.0.0.1",
        usuario=None,
        contenido_raw="linea de prueba para validar db_writer.py",
        modulo="modulo_iv",
    )
    print(f"[+] Evento raw insertado con id: {evento_id}")

    alarma_id = insertar_alarma(
        conn,
        timestamp=datetime.datetime.now(datetime.UTC),
        tipo_alarma="PRUEBA_DB_WRITER",
        ip_origen="127.0.0.1",
        modulo="modulo_iv",
        detalle={"nota": "prueba manual de db_writer.py"},
    )
    print(f"[+] Alarma insertada con id: {alarma_id}")

    conn.close()
