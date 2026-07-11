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

def apply_tmp_hardening():
    print("Aplicando hardening al montaje de /tmp (noexec, nosuid)...")

    # 1. Copiar el archivo de montaje por defecto de systemd a la zona de configuración del administrador
    # Esto evita que se pise con actualizaciones del sistema.
    src_mount = "/usr/lib/systemd/system/tmp.mount"
    dst_mount = "/etc/systemd/system/tmp.mount"

    if os.path.exists(src_mount) and not os.path.exists(dst_mount):
        print("[*] Copiando unidad tmp.mount por defecto a /etc/systemd/system/...")
        success, err = run_command(f"cp {src_mount} {dst_mount}")
        if not success:
            print(f"❌ Error al copiar tmp.mount: {err}")
            sys.exit(1)

    # 2. Modificar las opciones en el archivo copiado para asegurar nodev, nosuid, noexec
    if os.path.exists(dst_mount):
        print("[*] Configurando opciones seguras en tmp.mount...")
        try:
            with open(dst_mount, "r") as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                if line.startswith("Options="):
                    # Forzamos que incluya mode=1777, strictatime, noexec, nosuid, nodev
                    line = "Options=mode=1777,strictatime,noexec,nosuid,nodev\n"
                new_lines.append(line)

            with open(dst_mount, "w") as f:
                f.writelines(new_lines)
        except Exception as e:
            print(f"❌ Error al editar tmp.mount: {e}")
            sys.exit(1)

    # 3. Recargar el demonio de systemd para que lea la nueva configuración
    print("[*] Recargando el demonio de systemd...")
    run_command("systemctl daemon-reload")

    # 4. Habilitar el servicio para que persista tras los reinicios y remontar en caliente
    print("[*] Habilitando y aplicando el montaje seguro...")
    run_command("systemctl enable tmp.mount")
    
    # Intentamos un remonte en caliente seguro para que impacte ya mismo
    success, err = run_command("mount -o remount,noexec,nosuid,nodev /tmp")
    
    if not success:
        # Si da error porque hay procesos usando /tmp activamente, forzamos el reinicio del servicio de montaje
        success, err = run_command("systemctl restart tmp.mount")

    if success:
        print("🚀 Hardening de /tmp aplicado exitosamente.")
    else:
        print(f"⚠️ Cambios guardados, pero se requiere reiniciar la VM para aplicar el montaje debido a procesos activos: {err}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse con privilegios de root (sudo).")
        sys.exit(1)
        
    apply_tmp_hardening()