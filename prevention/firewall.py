#!/usr/bin/env python3
import os
import subprocess
import sys

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip()

def get_main_interface():
    """Detecta de forma dinamica la interfaz de red activa principal."""
    # Buscamos la interfaz que maneja la ruta por defecto (default gateway)
    success, output = run_command("ip route show default")
    if success and "dev" in output:
        parts = output.split()
        try:
            dev_index = parts.index("dev")
            return parts[dev_index + 1]
        except (ValueError, IndexError):
            pass
    
    # Fallback: Listar interfaces activas omitiendo 'lo'
    success, output = run_command("ip -o link show up")
    if success:
        for line in output.splitlines():
            parts = line.split(":")
            if len(parts) > 1:
                ifname = parts[1].strip()
                if ifname != "lo" and not ifname.startswith("veth"):
                    return ifname
    return None

def apply_firewall_hardening():
    print("Aplicando hardening de Firewalld...")
    changes_made = False
    TARGET_ZONE = "drop"  # Zona restrictiva recomendada por CIS

    # 1. DETECCIÓN Y ACTIVACIÓN DEL SERVICIO
    success, state = run_command("systemctl is-active firewalld")
    if state != "active":
        print(f"[+] Firewalld no estaba activo (Estado: {state}). Levantando servicio...")
        run_command("systemctl enable --now firewalld")
        changes_made = True
    else:
        print("[*] El servicio firewalld ya se encuentra activo.")

    # 2. DETECCIÓN Y CONFIGURACIÓN DE LA ZONA POR DEFECTO
    success, current_zone = run_command("firewall-cmd --get-default-zone")
    if not success:
        print(f"❌ Error al interactuar con firewalld: {current_zone}")
        sys.exit(1)

    print(f"[*] Zona por defecto actual: '{current_zone}'")

    if current_zone != TARGET_ZONE:
        print(f"[+] Cambiando zona por defecto a '{TARGET_ZONE}'...")
        success_set, err_set = run_command(f"firewall-cmd --set-default-zone={TARGET_ZONE}")
        if success_set:
            print(f"[+] Zona por defecto cambiada a '{TARGET_ZONE}' con exito.")
            changes_made = True
        else:
            print(f"❌ Error al cambiar zona por defecto: {err_set}")
    else:
        print(f"[*] La zona por defecto ya cumple con la politica segura ('{TARGET_ZONE}').")

    # 3. COMPROBACIÓN DE ASIGNACIÓN DE LA INTERFAZ DE RED
    interface = get_main_interface()
    if interface:
        print(f"[*] Interfaz de red principal detectada: '{interface}'")
        # Verificar a que zona pertenece esa interfaz en caliente
        _, active_zone = run_command(f"firewall-cmd --get-zone-of-interface={interface}")
        
        # Si la interfaz no esta explícitamente en la zona objetivo o por defecto
        if TARGET_ZONE not in active_zone.lower() and "no zone" in active_zone.lower():
            print(f"[+] Asignando interfaz {interface} a la zona '{TARGET_ZONE}' de forma permanente...")
            run_command(f"firewall-cmd --permanent --zone={TARGET_ZONE} --add-interface={interface}")
            changes_made = True
        else:
            print(f"[*] La interfaz {interface} ya se encuentra protegida bajo la zona activa.")
    else:
        print("⚠️ No se pudo determinar la interfaz de red principal de forma automatica.")

    # 4. CONFIGURACIÓN DE PUERTOS PERMITIDOS EXPLICITAMENTE
    # Comprobamos si el puerto del panel (8000) ya está añadido de forma permanente para evitar falsos positivos
    _, check_8000 = run_command(f"firewall-cmd --permanent --zone={TARGET_ZONE} --query-port=8000/tcp")
    if check_8000 != "yes":
        print(f"[+] Abriendo puerto 8000/tcp de manera permanente en la zona '{TARGET_ZONE}'...")
        run_command(f"firewall-cmd --permanent --zone={TARGET_ZONE} --add-port=8000/tcp")
        changes_made = True

    _, check_2222 = run_command(f"firewall-cmd --permanent --zone={TARGET_ZONE} --query-port=2222/tcp")
    if check_2222 != "yes":
        print(f"[+] Abriendo puerto 2222/tcp de manera permanente en la zona '{TARGET_ZONE}'...")
        run_command(f"firewall-cmd --permanent --zone={TARGET_ZONE} --add-port=2222/tcp")
        changes_made = True

    # 5. RECARGAR SI HUBO CAMBIOS PERMANENTES
    if changes_made:
        print("[*] Aplicando cambios permanentes en las reglas de Firewalld...")
        run_command("firewall-cmd --reload")
        print("🚀 Hardening de Firewalld completado con éxito.")
    else:
        print("✅ No se requirieron cambios. El firewall ya se encuentra restrictivo y en regla.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse con privilegios de root (sudo).")
        sys.exit(1)

    apply_firewall_hardening()