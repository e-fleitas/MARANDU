#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Database Hardening Enforcement (Definitive Version)
File: prevention/db_auth.py
"""

import argparse
import os
import secrets
import subprocess
import sys
from pathlib import Path


def grant_postgres_permissions():
    """
    Configura permisos dinámicos con ACL para que el usuario 'postgres'
    pueda navegar por el proyecto y leer el script de validación.
    """
    print("[*] HIPS: Configurando permisos dinámicos para el entorno de PostgreSQL...")

    proj_dir = Path(__file__).resolve().parent.parent
    parent_1 = proj_dir.parent
    parent_2 = parent_1.parent

    for path in [parent_2, parent_1, proj_dir, proj_dir / "tests"]:
        if path.exists():
            subprocess.run(["setfacl", "-m", "u:postgres:x", str(path)], stderr=subprocess.DEVNULL)

    validator_path = proj_dir / "tests" / "db_hardening_check.py"
    if validator_path.is_file():
        subprocess.run(["setfacl", "-m", "u:postgres:r", str(validator_path)], stderr=subprocess.DEVNULL)
        print("[OK] Permisos ACL aplicados de forma transparente para PostgreSQL.")


# --- CONFIGURACIÓN DE RUTAS ---
POSIBLES_RUTAS = ["/var/lib/pgsql/16/data", "/var/lib/pgsql/data"]
PG_DATA_DIR = next((r for r in POSIBLES_RUTAS if os.path.exists(r)), None)

if not PG_DATA_DIR:
    print("[-] Error: No se encontró el directorio de datos de PostgreSQL.", file=sys.stderr)
    sys.exit(1)

POSTGRESQL_AUTO_CONF = os.path.join(PG_DATA_DIR, "postgresql.auto.conf")
PG_HBA_CONF = os.path.join(PG_DATA_DIR, "pg_hba.conf")
SSL_CERT_FILE = os.path.join(PG_DATA_DIR, "server.crt")
SSL_KEY_FILE = os.path.join(PG_DATA_DIR, "server.key")


def parse_arguments():
    parser = argparse.ArgumentParser(description="M.A.R.A.N.D.U. - Aplicador de Hardening")
    parser.add_argument("-p", "--password", required=True, help="Contraseña para marandu_app")
    parser.add_argument("-d", "--dbname", default="postgres", help="DB objetivo")
    parser.add_argument("-u", "--user", default="postgres", help="Usuario admin")
    return parser.parse_args()


def run_sql(query, admin_user, dbname):
    """Ejecuta SQL con el usuario y DB especificados."""
    cmd = ["sudo", "-i", "-u", admin_user, "psql", "-d", dbname, "-c", query]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode == 0


def sql_dollar_quote(raw: str) -> str:
    """
    Envuelve un literal en dollar-quoting de PostgreSQL con un tag aleatorio,
    evitando el escapeo manual de comillas simples (que es frágil y es lo que
    causaba la inyección original al interpolar la password directo en el
    string SQL). Con un tag aleatorio de 8 hex, la probabilidad de colisión
    con el contenido del literal es despreciable, y aun si colisionara el
    comando simplemente fallaría (no se ejecutaría SQL no intencionado).
    """
    tag = secrets.token_hex(4)
    return f"${tag}${raw}${tag}$"


def ensure_ssl_certificate():
    """
    Asegura que exista un certificado SSL autofirmado para PostgreSQL antes
    de escribir 'ssl = on' en postgresql.auto.conf.

    Sin esto, PostgreSQL falla al arrancar con 'ssl = on' si no encuentra
    server.crt/server.key en el data dir (o directamente ignora/pierde la
    directiva en el próximo ALTER SYSTEM, según cómo haya fallado el intento
    previo de arranque) -- este fue el bug real que rompía el control 1 y,
    de rebote, dejaba a medias todo postgresql.auto.conf.
    """
    cert = Path(SSL_CERT_FILE)
    key = Path(SSL_KEY_FILE)

    if cert.exists() and key.exists():
        print("[ ] Certificado SSL de PostgreSQL ya existe, no se regenera.")
        return

    print("[+] No se encontró certificado SSL para PostgreSQL. Generando uno autofirmado...")
    result = subprocess.run(
        [
            "sudo", "-u", "postgres", "openssl", "req", "-new", "-x509",
            "-days", "365", "-nodes",
            "-out", str(cert),
            "-keyout", str(key),
            "-subj", "/CN=marandu-server",
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )

    if result.returncode != 0 or not cert.exists() or not key.exists():
        print("[-] Advertencia: no se pudo generar el certificado SSL automáticamente.", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return

    # Permisos estrictos sobre la clave privada (PostgreSQL rechaza arrancar
    # si server.key es legible por otros).
    subprocess.run(["sudo", "chmod", "600", str(key)])
    subprocess.run(["sudo", "chown", "postgres:postgres", str(cert), str(key)])
    print("[OK] Certificado SSL generado y permisos aplicados.")


def main():
    if os.getuid() != 0:
        print("[-] Este script requiere privilegios de root.")
        sys.exit(1)

    args = parse_arguments()
    grant_postgres_permissions()

    print("[*] Aplicando hardening...")

    # Acumulamos el resultado de cada paso para poder reportar con precisión
    # qué falló. Antes, el script imprimía "Hardening aplicado con éxito" de
    # forma incondicional al llegar al final, sin chequear el returncode de
    # ningún run_sql (salvo el de "role_exists") -- eso generaba falsos
    # positivos: el script decía "éxito" aunque varios controles CIS hubieran
    # fallado en silencio (por ejemplo, por un problema de autenticación
    # contra 'postgres' que impedía CUALQUIER escritura vía ALTER SYSTEM).
    resultados = []

    # 0. Asegurar certificado SSL antes de exigir 'ssl = on'
    ensure_ssl_certificate()

    # 1. Configuración global (auto.conf)
    directives = (
        "ssl = on\n"
        "log_connections = on\n"
        "log_disconnections = on\n"
        "password_encryption = scram-sha-256\n"
        "shared_preload_libraries = 'pgaudit'\n"
    )
    try:
        with open(POSTGRESQL_AUTO_CONF, "w") as f:
            f.write(directives)
        subprocess.run(["chown", f"{args.user}:{args.user}", POSTGRESQL_AUTO_CONF])
        resultados.append(("Escritura de postgresql.auto.conf", True))
    except OSError as e:
        print(f"[-] Error escribiendo {POSTGRESQL_AUTO_CONF}: {e}", file=sys.stderr)
        resultados.append(("Escritura de postgresql.auto.conf", False))

    # 2. pg_hba.conf seguro
    if os.path.exists(PG_HBA_CONF):
        try:
            with open(PG_HBA_CONF, "r") as f:
                content = f.read().replace("md5", "scram-sha-256").replace("ident", "scram-sha-256")
            with open(PG_HBA_CONF, "w") as f:
                f.write(content)
            resultados.append(("Actualización de pg_hba.conf", True))
        except OSError as e:
            print(f"[-] Error actualizando {PG_HBA_CONF}: {e}", file=sys.stderr)
            resultados.append(("Actualización de pg_hba.conf", False))
    else:
        print(f"[-] Advertencia: no se encontró {PG_HBA_CONF}.", file=sys.stderr)
        resultados.append(("Actualización de pg_hba.conf", False))

    # 3. Aplicar configuración en caliente y reiniciar
    restart_ok = subprocess.run(["systemctl", "restart", "postgresql"]).returncode == 0
    resultados.append(("Reinicio de PostgreSQL (fase 1)", restart_ok))

    if not restart_ok:
        print("[-] PostgreSQL no pudo reiniciar. Verificá 'systemctl status postgresql' "
              "y los logs en el data dir antes de continuar.", file=sys.stderr)

    # 4. Configuración de seguridad en la DB
    # ⚡ La contraseña sigue viniendo de MARANDU_DB_APP_PASSWORD (variable de
    # entorno del server, nunca del cliente web), pero ahora se envuelve con
    # dollar-quoting en vez de interpolarse cruda entre comillas simples:
    # así una comilla dentro del password no puede romper la sentencia SQL
    # ni inyectar código adicional.
    role_exists = run_sql(
        "SELECT 1 FROM pg_roles WHERE rolname = 'marandu_app';", args.user, "postgres"
    )
    quoted_password = sql_dollar_quote(args.password)
    if role_exists:
        ok = run_sql(f"ALTER ROLE marandu_app WITH PASSWORD {quoted_password};", args.user, "postgres")
        resultados.append(("ALTER ROLE marandu_app (password)", ok))
    else:
        ok = run_sql(f"CREATE ROLE marandu_app WITH LOGIN PASSWORD {quoted_password};", args.user, "postgres")
        resultados.append(("CREATE ROLE marandu_app", ok))

    ok = run_sql("ALTER ROLE marandu_app NOSUPERUSER NOCREATEDB NOCREATEROLE;", args.user, "postgres")
    resultados.append(("ALTER ROLE marandu_app (restricciones)", ok))

    # Revocar privilegios públicos (Control 6)
    ok = run_sql("REVOKE ALL ON SCHEMA public FROM PUBLIC;", args.user, args.dbname)
    resultados.append(("REVOKE ALL ON SCHEMA public", ok))
    ok = run_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC;", args.user, args.dbname)
    resultados.append(("REVOKE CREATE ON SCHEMA public", ok))
    ok = run_sql("REVOKE USAGE ON SCHEMA public FROM PUBLIC;", args.user, args.dbname)
    resultados.append(("REVOKE USAGE ON SCHEMA public", ok))

    # Activar pgaudit (Control 7)
    ok = run_sql("CREATE EXTENSION IF NOT EXISTS pgaudit;", args.user, args.dbname)
    resultados.append(("CREATE EXTENSION pgaudit", ok))
    ok = run_sql("ALTER SYSTEM SET pgaudit.log = 'all';", args.user, "postgres")
    resultados.append(("ALTER SYSTEM SET pgaudit.log", ok))

    # 5. Reinicio final para aplicar cambios de ALTER SYSTEM
    restart_final_ok = subprocess.run(["systemctl", "restart", "postgresql"]).returncode == 0
    resultados.append(("Reinicio de PostgreSQL (fase 2)", restart_final_ok))

    ok = run_sql("SELECT pg_reload_conf();", args.user, "postgres")
    resultados.append(("pg_reload_conf()", ok))

    # --- Resumen final: ya no se imprime "éxito" de forma incondicional ---
    fallidos = [nombre for nombre, exito in resultados if not exito]
    if not fallidos:
        print("[+] Hardening aplicado con éxito.")
        sys.exit(0)
    else:
        print("[-] Hardening aplicado CON ERRORES. Los siguientes pasos fallaron:", file=sys.stderr)
        for nombre in fallidos:
            print(f"    - {nombre}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()