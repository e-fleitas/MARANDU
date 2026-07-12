#!/bin/bash
# ==============================================================================
# M.A.R.A.N.D.U. - Script de Configuración del Entorno (Rocky Linux 9)
# ==============================================================================
set -e

# Asegurar que se ejecuta con privilegios de root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Error: Este script debe ser ejecutado como root o usando sudo."
    exit 1
fi

echo "=============================================================================="
echo "[+] Iniciando configuración del entorno base para M.A.R.A.N.D.U..."
echo "=============================================================================="

# 1. Instalar dependencias necesarias
echo "[+] Instalando dependencias del sistema..."
dnf install -y python3 python3-pip pgaudit_16 openssh-server audit

# 2. Crear el usuario del sistema restringido 'marandu'
if ! id "marandu" &>/dev/null; then
    echo "[+] Creando usuario de sistema aislado 'marandu'..."
    useradd -r -m -s /bin/bash marandu
else
    echo "[ ] El usuario 'marandu' ya existe en el sistema."
fi

# Determinar directorio actual
PROJ_DIR=$(pwd)

# 3. Configurar reglas granulares en Sudoers
# Esto permite que el usuario 'marandu' ejecute los scripts sin pedir contraseña
echo "[+] Configurando /etc/sudoers.d/marandu..."
cat << EOF > /etc/sudoers.d/marandu
# === Permisos para Scripts de Endurecimiento ===
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/ssh_hardening.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/selinux.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/sysctl.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/secure_tmp_mount.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/pam_faillock.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/password_hardening.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/rsyslog_centralization.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/firewall.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/auditd.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/db_auth.py

# === Permisos para Módulos de Diagnóstico ===
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/tests/hardening_check.py
marandu ALL=(root) NOPASSWD: /usr/bin/python3 $PROJ_DIR/tests/db_hardening_check.py

# === Binarios Nativos ===
marandu ALL=(root) NOPASSWD: /usr/sbin/sshd -T
marandu ALL=(root) NOPASSWD: /usr/sbin/auditctl -l
EOF

# Aplicar permisos restrictivos
chmod 0440 /etc/sudoers.d/marandu

# 4. Ajustar la propiedad y permisos del directorio
# Esto garantiza que el usuario marandu sea dueño de los archivos y pueda ejecutarlos
echo "[+] Aplicando propiedad a $PROJ_DIR..."
chown -R marandu:marandu "$PROJ_DIR"
chmod -R 750 "$PROJ_DIR"

echo "=============================================================================="
echo "[✓] Configuración finalizada."
echo "Para continuar con la instalación web, ejecuta el siguiente comando:"
echo "    sudo -u marandu ./setup_web.sh"
echo "=============================================================================="