#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Prevention Module
File: prevention/rsyslog_centralization.py

Configura la centralización de logs hacia el servidor remoto, asegura la 
retención local en el directorio mandatorio /var/log/hips/ y establece 
las directivas de rotación con logrotate para evitar denegación de servicio 
por llenado de disco.
"""

import os
import subprocess
import sys

LOGS_DIR = "/var/log/hips"
RSYSLOG_CONF = "/etc/rsyslog.d/centralizado.conf"
LOGROTATE_CONF = "/etc/logrotate.d/hips"
REMOTE_SYSLOG_SERVER = "192.168.0.100:514"

def run_command(command):
    """Ejecuta un comando de sistema de forma segura."""
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al ejecutar '{command}': {e.stderr.strip()}", file=sys.stderr)
        return None

def configure_rsyslog():
    print("[*] Iniciando configuración de rsyslog...")

    # 1. Crear el directorio mandatorio para retención local de logs
    if not os.path.exists(LOGS_DIR):
        print(f"[+] Creando directorio de logs local: {LOGS_DIR}")
        os.makedirs(LOGS_DIR, mode=0o750, exist_ok=True)
    else:
        print(f"[. ] El directorio {LOGS_DIR} ya existe.")

    # 2. Escribir configuración de rsyslog (Envío remoto + Retención local)
    print(f"[+] Generando archivo de configuración en {RSYSLOG_CONF}")
    rsyslog_content = f"""# Configuración de Centralización y Hardening HIPS - M.A.R.A.N.D.U.

# Regla de Retención Local Mandatoria (Escribe copias locales en el path del HIPS)
*.* {LOGS_DIR}/syslog.log

# Regla de Reenvío Remoto al Servidor Centralizador
*.* @{REMOTE_SYSLOG_SERVER}
"""
    try:
        with open(RSYSLOG_CONF, "w") as f:
            f.write(rsyslog_content)
        os.chmod(RSYSLOG_CONF, 0o644)
    except IOError as e:
        print(f"[-] Error al escribir {RSYSLOG_CONF}: {e}", file=sys.stderr)
        return False

    # 3. Reiniciar el servicio de rsyslog para aplicar los cambios en caliente
    print("[+] Reiniciando el servicio rsyslog...")
    if run_command("systemctl restart rsyslog") is not None:
        print("[+] rsyslog configurado y reiniciado con éxito.")
    else:
        print("[-] Falló el reinicio de rsyslog.", file=sys.stderr)
        return False
        
    return True

def configure_logrotate():
    """Configura la política de rotación para evitar que /var/log/hips sature el disco."""
    print(f"[*] Configurando directivas de logrotate en {LOGROTATE_CONF}...")
    
    logrotate_content = f"""{LOGS_DIR}/*.log {{
    weekly
    rotate 4
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}}
"""
    try:
        with open(LOGROTATE_CONF, "w") as f:
            f.write(logrotate_content)
        os.chmod(LOGROTATE_CONF, 0o644)
        print("[+] logrotate para el HIPS configurado exitosamente (Retención semanal/comprimido).")
        return True
    except IOError as e:
        print(f"[-] Error al escribir {LOGROTATE_CONF}: {e}", file=sys.stderr)
        return False

def main():
    if os.geteuid() != 0:
        print("[-] Este script requiere privilegios de root (sudo).", file=sys.stderr)
        sys.exit(1)

    success_rsyslog = configure_rsyslog()
    success_logrotate = configure_logrotate()

    if success_rsyslog and success_logrotate:
        print("[+] Hardening e Integración de Logs completada con éxito.")
    else:
        print("[-] Se presentaron errores durante la configuración de logs.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()