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

# 1. Agregar repositorio oficial de PostgreSQL (Requisito para pgaudit_16)
echo "[+] Configurando repositorio oficial de PostgreSQL (PGDG) para pgaudit..."
dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm

# 2. Instalar dependencias del sistema operativo
echo "[+] Instalando paquetes y dependencias del sistema..."
dnf install -y python3 python3-pip python3-devel gcc pgaudit_16 openssh-server audit

# 3. Crear el usuario del sistema restringido 'marandu'
if ! id "marandu" &>/dev/null; then
    echo "[+] Creando usuario de sistema aislado 'marandu'..."
    useradd -r -m -s /bin/bash marandu
else
    echo "[ ] El usuario 'marandu' ya existe en el sistema."
fi

# Determinar de forma dinámica el directorio actual del proyecto
PROJ_DIR=$(pwd)

# 4. Configurar reglas granulares en Sudoers (Principio de Mínimos Privilegios)
# Se incluyen los binarios nativos del OS para evitar bloqueos en el Dashboard Web.
echo "[+] Inyectando directivas de ejecución segura en /etc/sudoers.d/marandu..."
cat << EOF > /etc/sudoers.d/marandu
# === Permisos para Scripts de Endurecimiento de M.A.R.A.N.D.U. ===
marandu ALL=(root) NOPASSWD: $PROJ_DIR/prevention/ssh_hardening.py
marandu ALL=(root) NOPASSWD: $PROJ_DIR/prevention/selinux.py
marandu ALL=(root) NOPASSWD: $PROJ_DIR/prevention/sysctl.py
marandu ALL=(root) NOPASSWD: $PROJ_DIR/prevention/secure_tmp_mount.py
marandu ALL=(root) NOPASSWD: $PROJ_DIR/prevention/pam_faillock.py
marandu ALL=(root) NOPASSWD: $PROJ_DIR/prevention/password_hardening.py
marandu ALL=(root) NOPASSWD: $PROJ_DIR/prevention/rsyslog_centralization.py

# === Permisos para Módulos de Diagnóstico y Auditoría ===
marandu ALL=(root) NOPASSWD: $PROJ_DIR/tests/hardening_check.py
marandu ALL=(root) NOPASSWD: $PROJ_DIR/tests/db_hardening_check.py

# === Binarios Nativos del Sistema requeridos por los análisis de Python ===
marandu ALL=(root) NOPASSWD: /usr/sbin/sshd -T
marandu ALL=(root) NOPASSWD: /usr/sbin/auditctl -l
EOF

# Aplicar permisos restrictivos correctos al archivo de sudoers
chmod 0440 /etc/sudoers.d/marandu
echo "[+] Archivo /etc/sudoers.d/marandu configurado correctamente."

# 5. Ajustar la propiedad y permisos del directorio del proyecto
echo "[+] Aplicando políticas de propiedad (ACL) al directorio del proyecto..."
chown -R marandu:marandu "$PROJ_DIR"
chmod -R 750 "$PROJ_DIR"

echo "=============================================================================="
echo "[✓] FASE 1 COMPLETADA: Entorno y privilegios del sistema configurados."
echo "Para continuar con la instalación web, ejecuta el siguiente comando:"
echo "    sudo -u marandu ./setup_web.sh"
echo "=============================================================================="