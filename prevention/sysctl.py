#!/usr/bin/env python3
import os
import subprocess
import sys

def run_command(command):
    """Ejecuta un comando del sistema de forma segura."""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip()

def apply_sysctl_hardening():
    print("Aplicando hardening de parámetros sysctl de red...")
    
    # El estándar moderno de systemd prefiere archivos en sysctl.d
    conf_file = "/etc/sysctl.d/99-sysctl.conf"
    changes_made = False

    # Parámetros críticos de red recomendados por CIS Benchmarks
    target_settings = {
        "net.ipv4.ip_forward": "0",                  # Desactivar forwarding de IP (No actuar como router)
        "net.ipv4.conf.all.forwarding": "0",
        "net.ipv4.conf.all.accept_source_route": "0", # Ignorar paquetes con enrutamiento de origen
        "net.ipv4.conf.default.accept_source_route": "0",
        "net.ipv4.conf.all.accept_redirects": "0",    # No aceptar redirecciones ICMP (Previene MitM)
        "net.ipv4.conf.default.accept_redirects": "0",
        "net.ipv4.conf.all.secure_redirects": "0",
        "net.ipv4.conf.default.secure_redirects": "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",  # Ignorar pings a la dirección de broadcast (Previene Smurf)
        "net.ipv4.conf.all.rp_filter": "1",           # Habilitar filtro de ruta inversa (Previene IP spoofing)
        "net.ipv4.conf.default.rp_filter": "1"
    }

    # Crear el archivo con permisos correctos si no existe en absoluto
    if not os.path.exists(conf_file):
        try:
            with open(conf_file, "w") as f:
                f.write("# Parámetros de red seguros - Configuración HIPS MARANDU\n")
            print(f"[+] Archivo de configuración creado desde cero: {conf_file}")
        except Exception as e:
            print(f"❌ Error al crear el archivo {conf_file}: {e}")
            sys.exit(1)

    try:
        # 1. Leer las directivas actuales escritas en el archivo
        with open(conf_file, "r") as f:
            lines = f.readlines()

        new_lines = []
        keys_found = set()

        # 2. Analizar y corregir líneas existentes
        for line in lines:
            stripped = line.strip()
            matched_key = None
            
            # Comprobar si la línea corresponde a alguna de nuestras llaves objetivo
            for key in target_settings.keys():
                if stripped.startswith(f"{key}") or stripped.startswith(f"#{key}"):
                    if "=" in stripped:
                        matched_key = key
                        break
            
            if matched_key:
                expected_line = f"{matched_key} = {target_settings[matched_key]}\n"
                if stripped != expected_line.strip():
                    new_lines.append(expected_line)
                    print(f"[+] Modificando parámetro en archivo: {matched_key} = {target_settings[matched_key]}")
                    changes_made = True
                else:
                    new_lines.append(line)
                keys_found.add(matched_key)
            else:
                new_lines.append(line)

        # 3. Agregar los parámetros que falten por completo
        for key, value in target_settings.items():
            if key not in keys_found:
                new_lines.append(f"{key} = {value}\n")
                print(f"[+] Añadiendo parámetro faltante: {key} = {value}")
                changes_made = True

        # 4. Guardar los cambios si los hubo
        if changes_made:
            with open(conf_file, "w") as f:
                f.writelines(new_lines)

    except Exception as e:
        print(f"❌ Error al manipular el archivo {conf_file}: {e}")
        sys.exit(1)

    # 5. Forzar la recarga de la configuración directo en el Kernel vivo
    print("[*] Sincronizando configuraciones en caliente con el kernel...")
    success, output = run_command(f"sysctl -p {conf_file}")
    
    if success:
        if changes_made:
            print("🚀 Parámetros aplicados y cargados exitosamente en memoria.")
        else:
            print("✅ No se requirieron cambios en disco. El kernel se resincronizó correctamente.")
    else:
        print(f"❌ Error al ejecutar sysctl -p: {output}")
        sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse con privilegios de root (sudo).")
        sys.exit(1)

    apply_sysctl_hardening()