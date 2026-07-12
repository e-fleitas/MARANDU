#!/usr/bin/env python3
import os
import subprocess
import re

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
                if re.match(rf"^#?\\s*{key}\b", stripped, re.IGNORECASE):
                    matched_key = key
                    break
                    
            if matched_key:
                if matched_key not in applied_keys:
                    new_lines.append(f"{matched_key} {target_configs[matched_key]}\n")
                    applied_keys.add(matched_key)
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
        subprocess.run(["semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", str(port)], capture_output=True)
        # Por si ya estaba listado, intentamos modificarlo
        subprocess.run(["semanage", "port", "-m", "-t", "ssh_port_t", "-p", "tcp", str(port)], capture_output=True)
        
        # 4. Configurar Firewalld (abrir puerto 2222)
        subprocess.run(["firewall-cmd", "--permanent", "--add-port", f"{port}/tcp"], capture_output=True)
        subprocess.run(["firewall-cmd", "--reload"], capture_output=True)
        
        # 5. Reiniciar el demonio sshd
        result_restart = subprocess.run(["systemctl", "restart", "sshd"], capture_output=True, text=True)
        
        if result_restart.returncode == 0:
            return {
                "status": "success", 
                "message": f"Hardening de SSH aplicado exitosamente. Puerto: {port}. Root y Password auth deshabilitados."
            }
        else:
            return {"status": "error", "message": f"Error al reiniciar sshd: {result_restart.stderr}"}
            
    except Exception as e:
        return {"status": "error", "message": f"Excepción al aplicar hardening: {str(e)}"}

if __name__ == "__main__":
    print("Aplicando hardening de SSH...")
    res = apply_ssh_hardening()
    print(res["message"])