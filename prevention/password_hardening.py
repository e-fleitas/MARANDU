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


def get_authselect_state():
    """Devuelve (profile_id, [features_activas]) leyendo 'authselect current'.
    Si algo falla, devuelve (None, [])."""
    success, output = run_command("authselect current")
    if not success or not output:
        return None, []

    profile = None
    features = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Profile ID:"):
            profile = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("- "):
            features.append(stripped[2:].strip())

    return profile, features


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

    # 5. Forzar a PAM a habilitar la característica usando authselect.
    #
    # Si el .conf tiene minlen/minclass/retry pero pam_pwquality.so no está
    # efectivamente incluido en el stack PAM activo, esos valores nunca se
    # aplican en un login real -- el archivo existe pero nadie lo lee.
    print("[*] Habilitando la característica with-pwquality en authselect...")
    success, output = run_command("authselect enable-feature with-pwquality")

    if success:
        print("🚀 Hardening de políticas de contraseñas aplicado con éxito.")
        return

    if "already enabled" in output.lower():
        print("🚀 Hardening de políticas de contraseñas ya estaba activo en authselect.")
        return

    # 'enable-feature' puede fallar con "Unknown profile feature" en perfiles
    # como 'local', donde with-pwquality no se activa incrementalmente sino
    # que hay que re-seleccionar el perfil completo incluyéndola. Para no
    # pisar features ya habilitadas (p.ej. with-faillock, activada por
    # pam_faillock.py), leemos primero el estado actual y las preservamos.
    print(f"[*] 'enable-feature' no funcionó ({output.strip()}); reintentando con 'select --force'...")

    profile, current_features = get_authselect_state()
    if not profile:
        print("⚠️ No se pudo determinar el perfil authselect activo (comando 'authselect current' falló).")
        print("🚀 El archivo pwquality.conf se actualizó correctamente de todos modos.")
        return

    features_to_apply = set(current_features)
    features_to_apply.add("with-pwquality")
    feature_args = " ".join(sorted(features_to_apply))

    retry_cmd = f"authselect select {profile} {feature_args} --force".strip()
    success_retry, output_retry = run_command(retry_cmd)

    if success_retry:
        print(f"🚀 Perfil '{profile}' re-seleccionado con with-pwquality habilitado "
              f"(features preservadas: {', '.join(sorted(features_to_apply)) or 'ninguna'}).")
    else:
        print(f"⚠️ El reintento con 'select --force' también falló: {output_retry.strip()}")
        print("🚀 El archivo pwquality.conf se actualizó correctamente de todos modos, "
              "pero revisar manualmente si pam_pwquality.so quedó incluido en el stack PAM.")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse con privilegios de root (sudo).")
        sys.exit(1)

    apply_password_hardening()