#!/usr/bin/env python3
import os
import subprocess
import sys

def run_command(command):
    """Ejecuta un comando del sistema de forma segura."""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def apply_pam_faillock():
    print("Aplicando hardening de PAM Faillock (Bloqueo por intentos fallidos)...")

    # Forzamos la habilitación de la característica with-faillock usando la ruta absoluta
    print("[*] Configurando authselect para incluir bloqueo por intentos fallidos...")
    success, err = run_command("/usr/bin/authselect enable-feature with-faillock")
    
    if not success:
        # Si ya estaba activo o da una advertencia menor, intentamos forzar la aplicación
        print(f"[*] Nota/Aviso al aplicar característica: {err.strip()}")
    
    # Aplicamos los cambios de forma global en los archivos PAM
    run_command("/usr/bin/authselect apply-changes")
    print("[+] Cambios de authselect aplicados.")

    # 2. Validar de forma preventiva que la configuración impactó en los archivos
    pam_configured = False
    files_to_check = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
    for file in files_to_check:
        if os.path.exists(file):
            with open(file, "r") as f:
                if "pam_faillock.so" in f.read():
                    pam_configured = True

    if pam_configured:
        print("🚀 Hardening de pam_faillock aplicado exitosamente.")
    else:
        print("❌ Error: El módulo pam_faillock.so no se detecta en los archivos PAM.")
        sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse con privilegios de root (sudo).")
        sys.exit(1)
        
    apply_pam_faillock()