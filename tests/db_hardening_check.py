#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Database Security Module
File: tests/db_hardening_check.py

Suite automatizada de diagnóstico de hardening para PostgreSQL basada estrictamente
en los 7 controles CIS definidos en la sección 1.3 del plan del proyecto.
"""

import argparse
import os
import subprocess
import sys

def parse_arguments():
    """Procesa los argumentos de línea de comandos para las credenciales de la DB."""
    parser = argparse.ArgumentParser(
        description="M.A.R.A.N.D.U. - Suite de Verificación de Hardening para Base de Datos"
    )
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Host de la DB (default: 127.0.0.1)")
    parser.add_argument("-P", "--port", default="5432", help="Puerto de la DB (default: 5432)")
    parser.add_argument("-u", "--user", default="postgres", help="Usuario auditor")
    parser.add_argument("-d", "--dbname", default="postgres", help="Nombre de la base de datos")
    parser.add_argument("-p", "--password", default=None, help="Contraseña del usuario")
    return parser.parse_args()

def run_psql_query(query, args):
    """Ejecuta una consulta SQL usando las credenciales dinámicas provistas."""
    psql_binary = "psql"
    posibles_binarios = ["/usr/pgsql-16/bin/psql", "/usr/bin/psql"]
    for ruta in posibles_binarios:
        if os.path.exists(ruta):
            psql_binary = ruta
            break

    try:
        env_vars = {"PGPASSWORD": args.password} if args.password else {}
        cmd = [
            psql_binary, "-h", args.host, "-p", args.port,
            "-U", args.user, "-d", args.dbname, "-t", "-A", "-c", query
        ]
        result = subprocess.run(
            cmd, env=env_vars, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None

# CONTROL 1: SSL Activo
def verify_encryption(args):
    status = run_psql_query("SHOW ssl;", args)
    return status == "on"

# CONTROL 2: Rol dedicado marandu_app sin superusuario
def verify_app_role(args):
    query = "SELECT concat(rolsuper, ',', rolcreatedb) FROM pg_roles WHERE rolname = 'marandu_app';"
    res = run_psql_query(query, args)
    if not res:
        return False
    return res == "f,f"

# CONTROL 3: log_connections y log_disconnections
def verify_session_logging(args):
    conn = run_psql_query("SHOW log_connections;", args)
    disconn = run_psql_query("SHOW log_disconnections;", args)
    return conn == "on" and disconn == "on"

# CONTROL 4: pg_hba.conf - control de acceso por host e hibridación OS
def verify_pg_hba_rules(args):
    query = "SELECT count(*) FROM pg_hba_file_rules WHERE auth_method = 'md5';"
    md5_count = run_psql_query(query, args)
    
    hba_path = "/var/lib/pgsql/data/pg_hba.conf"
    if not os.path.exists(hba_path) and os.path.exists("/var/lib/pgsql/16/data/pg_hba.conf"):
        hba_path = "/var/lib/pgsql/16/data/pg_hba.conf"

    file_safe = True
    if os.path.exists(hba_path) and os.access(hba_path, os.R_OK):
        try:
            with open(hba_path, "r") as f:
                content = f.read()
                if "md5" in content and not "#" in content.split("md5")[0]:
                    file_safe = False
        except IOError:
            pass

    if md5_count is None:
        return False
    return int(md5_count) == 0 and file_safe

# CONTROL 5: Encriptación por defecto en scram-sha-256
def verify_auth_method(args):
    method = run_psql_query("SHOW password_encryption;", args)
    return method == "scram-sha-256"

# CONTROL 6: Comprobar que PUBLIC no tiene privilegios
def verify_public_privileges(args):
    # Esta consulta verifica si el grupo 'PUBLIC' tiene algún privilegio, ignorando al dueño
    query = """
    SELECT count(*) 
    FROM pg_namespace n, aclexplode(n.nspacl) a 
    WHERE n.nspname = 'public' 
    AND a.grantee = 0;
    """
    # Si la revocación fue exitosa, el grupo PUBLIC (grantee 0) no debe aparecer en el ACL del esquema.
    res = run_psql_query(query, args)
    return res == "0"

# CONTROL 7: Comprobar pgaudit
def verify_pgaudit(args):
    # Verificamos si la extensión existe
    ext_installed = run_psql_query("SELECT count(*) FROM pg_extension WHERE extname = 'pgaudit';", args)
    if ext_installed != "1": return False
    
    # Verificamos si log está activo (usamos un SELECT directo sobre pg_settings)
    # A veces pgaudit.log requiere que se cargue la librería, esto confirma que está activa.
    val = run_psql_query("SELECT setting FROM pg_settings WHERE name = 'pgaudit.log';", args)
    return val is not None and val != "" and val != "none"

def main():
    args = parse_arguments()

    print("==================================================")
    print(" M.A.R.A.N.D.U. - AUDITORÍA COMPLETA HARDENING DB ")
    print(f" Target: {args.user}@{args.host}:{args.port}/{args.dbname}")
    print("==================================================")

    results = {
        "1. Cifrado TLS/SSL Activo (ssl=on)": verify_encryption(args),
        "2. Rol 'marandu_app' sin Superusuario": verify_app_role(args),
        "3. Registro de Auditoría (connections/disconnections)": verify_session_logging(args),
        "4. Control Restrictivo de Hosts (pg_hba.conf sin md5)": verify_pg_hba_rules(args),
        "5. Algoritmo de Hashing Seguro (scram-sha-256)": verify_auth_method(args),
        "6. Restricción de Privilegios Públicos en Schema Public": verify_public_privileges(args),
        "7. Extensión pgaudit Instalada y Configurada": verify_pgaudit(args)
    }

    all_passed = True
    for check, passed in results.items():
        status = "[ PASSED ]" if passed else "[ FAILED ]"
        print(f"{status:<10} - {check}")
        if not passed:
            all_passed = False

    print("==================================================")
    if all_passed:
        print("[+] COMPLIANCE OK: La base de datos supera los controles CIS.")
        sys.exit(0)
    else:
        print("[-] COMPLIANCE FAIL: Se detectaron debilidades de hardening.")
        sys.exit(1)

if __name__ == "__main__":
    main()