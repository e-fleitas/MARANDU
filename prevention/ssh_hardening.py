#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys


def apply_ssh_hardening(port=2222):
    """
    Aplica el hardening de SSH:
    1. Cambia el puerto por defecto a 2222.
    2. Deshabilita el login de root.
    3. Exige autenticación por clave pública (deshabilita contraseña).
    4. Configura firewalld y SELinux.
    """
    config_path = "/etc/ssh/sshd_config"

    if os.getuid() != 0:
        return {"status": "error", "message": "Se requieren privilegios de root (sudo) para aplicar esta medida."}

    warnings = []

    try:
        # 1. Leer la configuración actual
        if not os.path.exists(config_path):
            return {"status": "error", "message": f"No se encontró el archivo {config_path}"}

        with open(config_path, "r") as f:
            lines = f.readlines()

        # Hacer un backup previo si no existe
        backup_path = f"{config_path}.bak"
        if not os.path.exists(backup_path):
            with open(backup_path, "w") as f_bak:
                f_bak.writelines(lines)

        # 2. Modificar o añadir las directivas requeridas
        target_configs = {
            "Port": str(port),
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PubkeyAuthentication": "yes"
        }

        new_lines = []
        applied_keys = set()

        for line in lines:
            stripped = line.strip()
            matched_key = None
            for key in target_configs:
                # FIX: antes era rf"^#?\\s*{key}\b" (raw f-string con doble backslash
                # literal), lo que buscaba un caracter '\' seguido de 's' repetidas veces
                # en vez de whitespace. Nunca hacía match contra sshd_config real, así que
                # el script agregaba las directivas al final sin tocar/comentar las
                # originales. sshd usa la PRIMERA ocurrencia activa de cada directiva, así
                # que las líneas viejas seguían siendo las efectivas.
                if re.match(rf"^#?\s*{key}\b", stripped, re.IGNORECASE):
                    matched_key = key
                    break

            if matched_key:
                if matched_key not in applied_keys:
                    new_lines.append(f"{matched_key} {target_configs[matched_key]}\n")
                    applied_keys.add(matched_key)
                # si ya se aplicó antes (línea duplicada en el archivo original),
                # se omite la línea vieja en vez de mantenerla o repetirla.
            else:
                new_lines.append(line)

        # Agregar las claves faltantes que no estaban originalmente
        for key, val in target_configs.items():
            if key not in applied_keys:
                new_lines.append(f"{key} {val}\n")

        # Escribir los cambios
        with open(config_path, "w") as f:
            f.writelines(new_lines)

        # 3. Configurar SELinux (necesario ya que está en modo Enforcing)
        # Añade el puerto 2222 al contexto ssh_port_t
        sel_add = subprocess.run(
            ["semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", str(port)],
            capture_output=True, text=True
        )
        if sel_add.returncode != 0:
            # Puede fallar porque el puerto ya está listado (no es un error real en ese caso)
            # o porque el puerto pertenece a otro tipo SELinux, o falta el paquete
            # policycoreutils-python-utils. Intentamos "modificar" como fallback y si eso
            # también falla, lo registramos como warning en vez de reportar éxito silencioso.
            sel_mod = subprocess.run(
                ["semanage", "port", "-m", "-t", "ssh_port_t", "-p", "tcp", str(port)],
                capture_output=True, text=True
            )
            if sel_mod.returncode != 0:
                warnings.append(
                    f"SELinux: no se pudo asociar el puerto {port} a ssh_port_t "
                    f"(semanage -a: {sel_add.stderr.strip()!r}, "
                    f"semanage -m: {sel_mod.stderr.strip()!r}). "
                    f"sshd podría no poder bindear el puerto si SELinux está en Enforcing."
                )

        # 4. Configurar Firewalld (abrir puerto 2222)
        fw_add = subprocess.run(
            ["firewall-cmd", "--permanent", "--add-port", f"{port}/tcp"],
            capture_output=True, text=True
        )
        if fw_add.returncode != 0:
            warnings.append(
                f"firewalld: no se pudo abrir el puerto {port}/tcp "
                f"({fw_add.stderr.strip()})."
            )
        else:
            fw_reload = subprocess.run(["firewall-cmd", "--reload"], capture_output=True, text=True)
            if fw_reload.returncode != 0:
                warnings.append(f"firewalld: --reload falló ({fw_reload.stderr.strip()}).")

        # 5. Reiniciar el demonio sshd
        result_restart = subprocess.run(["systemctl", "restart", "sshd"], capture_output=True, text=True)

        if result_restart.returncode == 0:
            resultado = {
                "status": "success",
                "message": f"Hardening de SSH aplicado exitosamente. Puerto: {port}. Root y Password auth deshabilitados."
            }
            if warnings:
                resultado["status"] = "success_with_warnings"
                resultado["warnings"] = warnings
            return resultado
        else:
            return {
                "status": "error",
                "message": f"Error al reiniciar sshd: {result_restart.stderr}",
                "warnings": warnings
            }

    except Exception as e:
        return {"status": "error", "message": f"Excepción al aplicar hardening: {str(e)}"}


if __name__ == "__main__":
    # Ejecución vía `sudo -n <venv>/bin/python3 ssh_hardening.py [puerto]` desde la app web
    # (usuario 'marandu', autorizado por la regla exacta en /etc/sudoers.d/marandu).
    # Cuando corre bajo sudo, os.getuid() ya devuelve 0 dentro de este proceso, así que
    # el chequeo de root de apply_ssh_hardening() se cumple sin cambios adicionales.
    #
    # Se imprime únicamente un JSON por stdout para que el llamador (el panel web) pueda
    # parsear el resultado de forma confiable, en vez de tener que interpretar texto libre.
    puerto = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
    resultado = apply_ssh_hardening(port=puerto)
    print(json.dumps(resultado))
    sys.exit(0 if resultado["status"] in ("success", "success_with_warnings") else 1)