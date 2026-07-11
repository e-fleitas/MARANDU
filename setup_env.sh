#!/bin/bash
# setup_env.sh - Instalador de dependencias para M.A.R.A.N.D.U

echo "=== Instalando dependencias del Sistema Operativo para el HIPS ==="

# Asegurar privilegios de root
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecuta este script usando sudo."
  exit 1
fi

# 1. Actualizar repositorios e instalar herramientas de SELinux, Auditoría y Red
dnf update -y
dnf install -y policycoreutils-python-utils audit firewalld rsyslog

# 2. Instalar dependencias para compilar cosas de Python si hiciera falta
dnf install -y python3-devel gcc

# Asegurar rsyslog en el setup de dependencias del sistema
dnf install -y rsyslog

# Asegurar authselect para el hardening de PAM
dnf install -y authselect

# Asegurar las utilidades completas de administración de auditd
dnf install -y audit
dnf install -y audit-rules

echo "=== Configurando enlaces de compatibilidad para herramientas de auditoría ==="
# Asegurar que auditctl esté visible en el PATH global para los scripts de testeo
ln -sf /usr/sbin/auditctl /usr/bin/auditctl

echo "=== Dependencias del sistema instaladas correctamente ==="