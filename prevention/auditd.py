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

def apply_auditd_hardening():
    print("Aplicando hardening de reglas de auditoría (auditd)...")

    # 1. Asegurar que el servicio esté habilitado
    print("[*] Habilitando el servicio auditd...")
    run_command("systemctl enable auditd")

    # 2. Definir las reglas requeridas
    config_dir = "/etc/audit/rules.d"
    rules_file = f"{config_dir}/audit.rules"

    audit_rules = [
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        "-w /etc/sudoers -p wa -k actions"
    ]

    try:
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)

        existing_content = ""
        if os.path.exists(rules_file):
            with open(rules_file, "r") as f:
                existing_content = f.read()

        with open(rules_file, "a") as f:
            for rule in audit_rules:
                if rule not in existing_content:
                    f.write(f"{rule}\n")
                    print(f"[+] Regla añadida al archivo de persistencia: {rule}")
    except Exception as e:
        print(f"❌ Error al escribir las reglas de auditd: {e}")
        sys.exit(1)

    # 3. Limpiar las reglas cargadas actualmente en el kernel antes de recargar.
    #
    # Por qué: si una ejecución anterior de este script tuvo que usar el
    # fallback de auditctl (ver más abajo), esas reglas quedan activas en el
    # kernel indefinidamente -- auditctl no persiste en /etc/audit/rules.d,
    # así que augenrules no tiene forma de saber que ya están cargadas.
    # La siguiente vez que augenrules --load intenta compilar y cargar el set
    # completo, el kernel rechaza la regla duplicada con
    # "Error sending add rule data request (Rule exists)" y aborta con error
    # en la línea correspondiente del audit.rules generado.
    #
    # auditctl -D vacía el ruleset del kernel (no toca los archivos en disco),
    # dejando el terreno limpio para que augenrules cargue el set completo
    # sin conflictos.
    print("[*] Limpiando reglas de auditoría cargadas en el kernel para evitar conflictos...")
    run_command("/usr/sbin/auditctl -D")

    # 4. Cargar las reglas usando rutas absolutas (/usr/sbin/)
    print("[*] Cargando nuevas reglas en el kernel...")
    success, err = run_command("/usr/sbin/augenrules --load")

    if not success:
        print(f"[-] augenrules falló: {err.strip()}")
        print("[-] Aplicando vía auditctl con ruta absoluta como fallback...")
        # Antes de agregar cada regla por este camino, comprobamos si ya está
        # cargada en el kernel para no repetir el mismo problema de origen.
        _, current_rules = run_command("/usr/sbin/auditctl -l")
        current_rules = current_rules or ""
        for rule in audit_rules:
            if rule not in current_rules:
                run_command(f"/usr/sbin/auditctl {rule}")
            else:
                print(f"[*] Regla ya presente en el kernel, se omite: {rule}")

    # 5. Verificar estado del servicio
    success, status = run_command("systemctl is-active auditd")
    if success and status.strip() == "active":
        print("🚀 Hardening de auditd aplicado en el sistema.")
    else:
        print("⚠️ El servicio auditd no está activo.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse con privilegios de root (sudo).")
        sys.exit(1)

    apply_auditd_hardening()