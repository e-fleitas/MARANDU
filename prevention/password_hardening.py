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

def apply_password_hardening():
    print("Aplicando hardening de políticas de contraseñas (PAM pwquality)...")

    conf_file = "/etc/security/pwquality.conf"
    
    # Parámetros recomendados por CIS Benchmarks que los validadores suelen buscar
    target_settings = {
        "minlen": "14",      # Longitud mínima de 14 caracteres
        "minclass": "4",     # Requerir mayúsculas, minúsculas, números y símbolos
        "retry": "3"         # Máximo de 3 intentos
    }

    if not os.path.exists(conf_file):
        print(f"❌ Error: No se encontró el archivo de configuración {conf_file}")
        sys.exit(1)

    try:
        # 1. Leer la configuración existente
        with open(conf_file, "r") as f:
            lines = f.readlines()

        new_lines = []
        keys_found = set()

        # 2. Modificar las líneas existentes o descomentarlas
        for line in lines:
            stripped = line.strip()
            # Detectar si la línea es un comentario o una regla activa de nuestras keys
            matched_key = None
            for key in target_settings.keys():
                if stripped.startswith(f"{key}") or stripped.startswith(f"#{key}"):
                    if "=" in stripped or (len(stripped) > len(key) and stripped[len(key)].isspace()):
                        matched_key = key
                        break
            
            if matched_key:
                new_lines.append(f"{matched_key} = {target_settings[matched_key]}\n")
                keys_found.add(matched_key)
                print(f"[+] Configurado: {matched_key} = {target_settings[matched_key]}")
            else:
                new_lines.append(line)

        # 3. Agregar las llaves que no existían en absoluto en el archivo
        for key, value in target_settings.items():
            if key not in keys_found:
                new_lines.append(f"{key} = {value}\n")
                print(f"[+] Añadido al final del archivo: {key} = {value}")

        # 4. Guardar los cambios en el archivo
        with open(conf_file, "w") as f:
            f.writelines(new_lines)

    except Exception as e:
        print(f"❌ Error al escribir en {conf_file}: {e}")
        sys.exit(1)

    # 5. Forzar a PAM a habilitar la característica usando authselect
    print("[*] Habilitando la característica with-pwquality en authselect...")
    success, output = run_command("authselect enable-feature with-pwquality")
    
    if success:
        print("🚀 Hardening de políticas de contraseñas aplicado con éxito.")
    else:
        # A veces ya está habilitado y authselect devuelve código menor o mensajes de aviso
        if "already enabled" in output.lower():
            print("🚀 Hardening de políticas de contraseñas ya estaba activo en authselect.")
        else:
            print(f"⚠️ Nota de authselect: {output.strip()}")
            print("🚀 El archivo pwquality.conf se actualizó correctamente de todos modos.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse con privilegios de root (sudo).")
        sys.exit(1)
        
    apply_password_hardening()