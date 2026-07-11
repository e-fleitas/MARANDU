#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Database Hardening Enforcement (Definitive Version)
File: prevention/db_auth.py
"""

import argparse
import os
import subprocess
import sys

# --- CONFIGURACIÓN DE RUTAS ---
POSIBLES_RUTAS = ["/var/lib/pgsql/16/data", "/var/lib/pgsql/data"]
PG_DATA_DIR = next((r for r in POSIBLES_RUTAS if os.path.exists(r)), None)

if not PG_DATA_DIR:
    print("[-] Error: No se encontró el directorio de datos de PostgreSQL.", file=sys.stderr)
    sys.exit(1)

POSTGRESQL_AUTO_CONF = os.path.join(PG_DATA_DIR, "postgresql.auto.conf")
PG_HBA_CONF = os.path.join(PG_DATA_DIR, "pg_hba.conf")

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

def main():
    if os.getuid() != 0:
        print("[-] Este script requiere privilegios de root.")
        sys.exit(1)

    args = parse_arguments()
    print("[*] Aplicando hardening...")

    # 1. Configuración global (auto.conf)
    directives = (
        "ssl = on\n"
        "log_connections = on\n"
        "log_disconnections = on\n"
        "password_encryption = scram-sha-256\n"
        "shared_preload_libraries = 'pgaudit'\n"
    )
    with open(POSTGRESQL_AUTO_CONF, "w") as f:
        f.write(directives)
    subprocess.run(["chown", f"{args.user}:{args.user}", POSTGRESQL_AUTO_CONF])

    # 2. pg_hba.conf seguro
    if os.path.exists(PG_HBA_CONF):
        with open(PG_HBA_CONF, "r") as f:
            content = f.read().replace("md5", "scram-sha-256").replace("ident", "scram-sha-256")
        with open(PG_HBA_CONF, "w") as f:
            f.write(content)

    # 3. Aplicar configuración en caliente y reiniciar
    subprocess.run(["systemctl", "restart", "postgresql-16"])

    # 4. Configuración de seguridad en la DB
    # Crear usuario
    run_sql(f"CREATE ROLE marandu_app WITH LOGIN PASSWORD '{args.password}';", args.user, "postgres")
    run_sql("ALTER ROLE marandu_app NOSUPERUSER NOCREATEDB NOCREATEROLE;", args.user, "postgres")

    # Revocar privilegios públicos (Control 6)
    run_sql("REVOKE ALL ON SCHEMA public FROM PUBLIC;", args.user, args.dbname)
    run_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC;", args.user, args.dbname)

    # Activar pgaudit (Control 7)
    run_sql("CREATE EXTENSION IF NOT EXISTS pgaudit;", args.user, args.dbname)
    run_sql("ALTER SYSTEM SET pgaudit.log = 'all, ddlog';", args.user, "postgres")

    # 5. Reinicio final para aplicar cambios de ALTER SYSTEM
    subprocess.run(["systemctl", "restart", "postgresql-16"])
    print("[+] Hardening aplicado con éxito.")

    # 6. Revocar privilegios públicos de forma absoluta
    # Revocamos explícitamente cualquier permiso de CREATE y USAGE a PUBLIC
    run_sql("REVOKE ALL ON SCHEMA public FROM PUBLIC;", args.user, args.dbname)
    run_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC;", args.user, args.dbname)
    run_sql("REVOKE USAGE ON SCHEMA public FROM PUBLIC;", args.user, args.dbname)

    # 7. Configurar pgaudit de forma persistente
    # Usamos ALTER SYSTEM para que persista incluso tras reinicios
    run_sql("ALTER SYSTEM SET pgaudit.log = 'all';", args.user, "postgres")
    run_sql("SELECT pg_reload_conf();", args.user, "postgres") # Recarga inmediata

if __name__ == "__main__":
    main()