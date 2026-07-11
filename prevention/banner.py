#!/usr/bin/env python3
import os
import subprocess
import sys

DEFAULT_BANNER = """
*******************************************************************************
*                                                                             *
*                ¡ADVERTENCIA! ACCESO RESTRINGIDO A MARANDU                   *
*                                                                             *
* Este sistema es privado y de uso exclusivo para el personal autorizado.     *
* Todas las actividades en este servidor son monitoreadas y registradas por   *
* el sistema de auditoria HIPS. El acceso no autorizado o el uso indebido     *
* seran sancionados conforme a las leyes vigentes.                           *
*                                                                             *
*******************************************************************************
"""

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def apply_banner(banner_text):
    print("Aplicando hardening del Banner de Login...")
    banner_text = banner_text.strip() + "\n"
    changes_made = False

    files_to_update = ["/etc/issue", "/etc/issue.net"]

    # 1. Aplicar y verificar /etc/issue y /etc/issue.net
    for filepath in files_to_update:
        current_content = ""
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                current_content = f.read()
        
        if current_content != banner_text:
            try:
                with open(filepath, "w") as f:
                    f.write(banner_text)
                print(f"[+] Banner aplicado exitosamente en: {filepath}")
                changes_made = True
            except Exception as e:
                print(f"❌ Error al escribir en {filepath}: {e}")
                sys.exit(1)
        else:
            print(f"[*] El banner ya estaba correctamente aplicado en: {filepath}")

    # 2. Configurar SSH para que muestre el banner remoto (/etc/issue.net)
    sshd_config = "/etc/ssh/sshd_config"
    target_line = "Banner /etc/issue.net"
    ssh_updated = False

    if os.path.exists(sshd_config):
        try:
            with open(sshd_config, "r") as f:
                lines = f.readlines()

            new_lines = []
            banner_configured = False

            for line in lines:
                stripped = line.strip()
                # Comprobar si la directiva ya está activa
                if stripped == target_line:
                    banner_configured = True
                    new_lines.append(line)
                # Comprobar si está comentada o tiene otra ruta
                elif stripped.startswith("Banner") or stripped.startswith("#Banner"):
                    new_lines.append(f"{target_line}\n")
                    banner_configured = True
                    ssh_updated = True
                    print(f"[+] SSH: Modificando directiva Banner existente por '{target_line}'")
                else:
                    new_lines.append(line)

            # Si no existía la palabra Banner en todo el archivo, la añadimos al final
            if not banner_configured:
                new_lines.append(f"\n{target_line}\n")
                ssh_updated = True
                print(f"[+] SSH: Añadiendo directiva '{target_line}' al final de la configuracion.")

            if ssh_updated:
                with open(sshd_config, "w") as f:
                    f.writelines(new_lines)
                changes_made = True

        except Exception as e:
            print(f"❌ Error al configurar SSHD: {e}")
            sys.exit(1)
    else:
        print("⚠️ No se encontro /etc/ssh/sshd_config. Saltando integracion con SSH.")

    # 3. Recargar el servicio SSH si hubo cambios en su configuracion
    if ssh_updated:
        print("[*] Reiniciando el servicio sshd para aplicar cambios...")
        success, err = run_command("systemctl restart sshd")
        if success:
            print("🚀 Servicio sshd reiniciado con exito.")
        else:
            print(f"❌ Error al reiniciar sshd: {err}")

    if changes_made:
        print("🚀 Hardening del banner completado.")
    else:
        print("✅ No se requirieron cambios. El banner ya estaba perfectamente configurado en todos lados.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse con privilegios de root (sudo).")
        sys.exit(1)

    # Permite recibir un string personalizado desde la terminal si queres cambiar el texto
    custom_banner = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BANNER
    apply_banner(custom_banner)