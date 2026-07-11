#!/bin/bash
# setup_env.sh - Instalador de dependencias para M.A.R.A.N.D.U

echo "=== Instalando dependencias del Sistema Operativo para el HIPS ==="

# Asegurar privilegios de root
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecuta este script usando sudo."
  exit 1
fi

# 1. Actualizar repositorios e instalar herramientas de SELinux, Auditoría, Red y Cifrado
dnf update -y
dnf install -y policycoreutils-python-utils audit firewalld rsyslog openssl

# 2. Instalar dependencias para compilar cosas de Python si hiciera falta
dnf install -y python3-devel gcc

# Asegurar rsyslog en el setup de dependencias del sistema
dnf install -y rsyslog

# Asegurar authselect para el hardening de PAM
dnf install -y authselect

# Asegurar las utilidades completas de administración de auditd
dnf install -y audit
dnf install -y audit-rules

dnf install -y pgaudit_16

# Agrega "acl" a tu lista de instalación de dnf
dnf install -y policycoreutils-python-utils audit firewalld rsyslog openssl pgaudit_16 acl

echo "=== Configurando permisos dinámicos para el auditor ==="
# Detectar la ruta absoluta de la instalación actual
PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_1="$(dirname "$PROJ_DIR")"
PARENT_2="$(dirname "$PARENT_1")"

# Otorgar permisos de ejecución (:x) necesarios para navegar hasta el script
setfacl -m u:postgres:x "$PARENT_2" 2>/dev/null || true
setfacl -m u:postgres:x "$PARENT_1" 2>/dev/null || true
setfacl -m u:postgres:x "$PROJ_DIR"
setfacl -m u:postgres:x "$PROJ_DIR/tests"

# Otorgar permiso de lectura al validador
if [ -f "$PROJ_DIR/tests/db_hardening_check.py" ]; then
  setfacl -m u:postgres:r "$PROJ_DIR/tests/db_hardening_check.py"
  echo "[OK] Permisos ACL aplicados de forma transparente para la entrega."
fi

echo "=== Configurando enlaces de compatibilidad para herramientas de auditoría ==="
# Asegurar que auditctl esté visible en el PATH global para los scripts de testeo
ln -sf /usr/sbin/auditctl /usr/bin/auditctl

echo "=== Dependencias del sistema instaladas correctamente ==="