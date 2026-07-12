#!/bin/bash
# setup_env.sh - Configurador del Sistema Operativo y Permisos para M.A.R.A.N.D.U

echo "================================================================="
echo "=== [PASO 1] Configurando Sistema Operativo y Usuario HIPS ====="
echo "================================================================="

# Asegurar privilegios de root para este script elemental
if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: Por favor, ejecuta este script usando sudo (sudo ./setup_env.sh)."
  exit 1
fi

# Detectar la ruta absoluta de la instalación actual
PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_1="$(dirname "$PROJ_DIR")"
PARENT_2="$(dirname "$PARENT_1")"

# 1. Actualizar repositorios e instalar paquetes de Rocky Linux
echo "[+] Actualizando el gestor de paquetes DNF..."
dnf update -y

echo "[+] Instalando herramientas de seguridad, auditoría, bases de datos y desarrollo..."
dnf install -y \
  policycoreutils-python-utils \
  audit \
  audit-rules \
  firewalld \
  rsyslog \
  openssl \
  authselect \
  acl \
  pgaudit_16 \
  python3-devel \
  gcc

echo "[+] Configurando enlaces de compatibilidad para herramientas de auditoría..."
ln -sf /usr/sbin/auditctl /usr/bin/auditctl

# 2. Creación y Aislamiento del usuario dedicado 'marandu'
echo "[+] Creando usuario del sistema 'marandu'..."
if ! id "marandu" &>/dev/null; then
  # Se crea como usuario de sistema, con home directory propio para su entorno de ejecución
  useradd -r -m -s /bin/bash marandu
  echo "[OK] Usuario 'marandu' creado."
else
  echo "[*] El usuario 'marandu' ya existe en el sistema."
fi

echo "[+] Configurando directorios de almacenamiento de alertas y logs..."
mkdir -p /var/log/hips
chown -R marandu:marandu /var/log/hips
chmod 750 /var/log/hips

# Entregar la propiedad del repositorio clonado a marandu para que gestione su venv
chown -R marandu:marandu "$PROJ_DIR"

# 3. Configuración de privilegios granulares en Sudoers
echo "[+] Aplicando políticas estrictas en /etc/sudoers.d/marandu..."
cat << EOF > /etc/sudoers.d/marandu
# Permitir a marandu ejecutar UNICAMENTE los scripts funcionales de hardening con sudo sin password
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/ssh_hardening.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/db_auth.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/firewall.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/selinux.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/sysctl.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/secure_tmp_mount.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/auditd.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/pam_faillock.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/password_hardening.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/prevention/banner.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/tests/hardening_check.py
marandu ALL=(ALL) NOPASSWD: /usr/bin/python3 $PROJ_DIR/tests/db_hardening_check.py
EOF
chmod 0440 /etc/sudoers.d/marandu

# 4. Configurar permisos dinámicos (ACLs) para el auditor de la base de datos
echo "[+] Aplicando permisos ACL de tránsito para el usuario postgres..."
setfacl -m u:postgres:x "$PARENT_2" 2>/dev/null || true
setfacl -m u:postgres:x "$PARENT_1" 2>/dev/null || true
setfacl -m u:postgres:x "$PROJ_DIR"
setfacl -m u:postgres:x "$PROJ_DIR/tests"

if [ -f "$PROJ_DIR/tests/db_hardening_check.py" ]; then
  setfacl -m u:postgres:r "$PROJ_DIR/tests/db_hardening_check.py"
  echo "[OK] Permisos ACL aplicados correctamente para la entrega."
fi

echo "================================================================="
echo "[OK] Fase del Sistema Operativo completada con éxito."
echo "[*] Siguiente paso, ejecuta: sudo -u marandu ./setup_web.sh"
echo "================================================================="