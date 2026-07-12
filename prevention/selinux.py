#!/usr/bin/env python3
import os
import subprocess
import sys

def run_command(command):
    """Ejecuta comandos de terminal de forma segura."""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip()

def apply_selinux_hardening():
    print("Aplicando hardening de SELinux...")
    changes_made = False

    # 1. DETECCIÓN Y APLICACIÓN EN CALIENTE (RUNTIME)
    success, getenforce_out = run_command("getenforce")
    if not success:
        print("❌ Error: No se pudo determinar el estado de SELinux en el kernel.")
        sys.exit(1)

    print(f"[*] Estado actual en memoria: {getenforce_out}")

    if getenforce_out != "Enforcing":
        if getenforce_out == "Disabled":
            print("⚠️ Alerta: SELinux está completamente deshabilitado en el kernel.")
            print("👉 Nota: Si SELinux fue desactivado vía GRUB, requerirá un reinicio completo tras modificar la configuración.")
        
        print("[+] Activando SELinux en modo Enforcing en caliente...")
        # Intentamos ponerlo en Enforcing (1)
        success_set, err_set = run_command("setenforce 1")
        if success_set:
            print("[+] SELinux conmutado exitosamente a Enforcing en memoria.")
            changes_made = True
        else:
            print(f"⚠️ No se pudo cambiar el modo en caliente (puede estar deshabilitado por completo): {err_set}")
    else:
        print("[*] SELinux ya se encuentra ejecutándose en modo Enforcing.")

    # 2. DETECCIÓN Y APLICACIÓN PERSISTENTE (ARCHIVO DE CONFIGURACIÓN)
    config_file = "/etc/selinux/config"
    if not os.path.exists(config_file):
        print(f"❌ Error: No se encontró el archivo de configuración {config_file}")
        sys.exit(1)

    try:
        with open(config_file, "r") as f:
            lines = f.readlines()

        new_lines = []
        config_updated = False
        target_setting = "SELINUX=enforcing"

        for line in lines:
            stripped = line.strip()
            # Buscamos la línea activa de configuración de SELINUX (evitando SELINUXTYPE)
            if stripped.startswith("SELINUX=") and not stripped.startswith("SELINUXTYPE="):
                if stripped != target_setting:
                    new_lines.append(f"{target_setting}\n")
                    config_updated = True
                    print(f"[+] Configuración persistente corregida: Modificado de '{stripped}' a '{target_setting}'")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        if config_updated:
            with open(config_file, "w") as f:
                f.writelines(new_lines)
            changes_made = True
        else:
            print("[*] La configuración persistente en /etc/selinux/config ya estaba en enforcing.")

    except Exception as e:
        print(f"❌ Error al procesar el archivo {config_file}: {e}")
        sys.exit(1)

    # 3. VEREDICTO FINAL
    if changes_made:
        print("🚀 Hardening de SELinux completado con éxito.")
    else:
        print("✅ No se requirieron cambios. SELinux ya está completamente blindado.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse con privilegios de root (sudo).")
        sys.exit(1)

    apply_selinux_hardening()