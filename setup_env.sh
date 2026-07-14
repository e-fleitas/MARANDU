#!/bin/bash
# ==============================================================================
# M.A.R.A.N.D.U. - Script de Configuración del Entorno (Rocky Linux 9)
# ==============================================================================
#
# Deja el sistema operativo listo para que el resto del pipeline funcione:
#   - Usuario de sistema aislado 'marandu' + sudoers granular (igual que antes).
#   - PostgreSQL 16 instalado, inicializado, con rol/DB propios y pgaudit
#     habilitado (session.py y models.py asumen esta base).
#   - firewalld activo (ip_block / ip_rate_limit de mitigation_actions.py
#     dependen de 'firewall-cmd' y de la zona 'drop').
#   - auditd y sshd habilitados.
#   - Un archivo .env con DATABASE_URL generado con una contraseña aleatoria,
#     nunca hardcodeada en el repo (session.py falla si no existe).
#
# Ejecutar como root. Variables opcionales:
#   DB_NAME (default: marandu)
#   DB_USER (default: marandu_app)   <- debe coincidir con PROTECTED_USERS
#                                       en prevention/mitigation_actions.py
# ==============================================================================
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[!] Error: Este script debe ser ejecutado como root o usando sudo."
    exit 1
fi

DB_NAME="${DB_NAME:-marandu}"
DB_USER="${DB_USER:-marandu_app}"

echo "=============================================================================="
echo "[+] Iniciando configuración del entorno base para M.A.R.A.N.D.U..."
echo "=============================================================================="

# 1. Instalar dependencias necesarias
echo "[+] Instalando dependencias del sistema..."
dnf install -y python3 python3-pip openssh-server audit firewalld

# PostgreSQL 16 (necesario para pgaudit_16). Según el repo disponible en tu
# imagen (AppStream module vs PGDG) el nombre exacto del paquete puede
# variar; se intentan las dos variantes más comunes.
if ! command -v psql &>/dev/null; then
    echo "[+] Instalando PostgreSQL 16 + pgaudit..."
    dnf module reset postgresql -y >/dev/null 2>&1 || true
    dnf module enable postgresql:16 -y >/dev/null 2>&1 || true
    if ! dnf install -y postgresql-server postgresql-contrib pgaudit_16; then
        echo "[!] No se pudo instalar vía AppStream; probando paquetes PGDG (postgresql16-*)..."
        dnf install -y postgresql16-server postgresql16-contrib postgresql16-pgaudit
    fi
else
    echo "[ ] PostgreSQL ya está instalado."
fi

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

# 4. Inicializar y habilitar PostgreSQL localmente
echo "[+] Inicializando PostgreSQL (si hace falta)..."
PGDATA_DIR=$(sudo -u postgres psql -tAc "SHOW data_directory;" 2>/dev/null || echo "/var/lib/pgsql/data")
if [ ! -f "$PGDATA_DIR/PG_VERSION" ]; then
    postgresql-setup --initdb 2>/dev/null || /usr/pgsql-16/bin/postgresql-16-setup initdb || {
        echo "[!] No se pudo inicializar automáticamente el cluster. Inicializalo a mano según tu instalación."
    }
fi
systemctl enable --now postgresql 2>/dev/null || systemctl enable --now postgresql-16 || true

# 5. Crear rol y base de datos dedicados, con password generada al azar
ENV_FILE="$PROJ_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "[+] Generando credenciales de base de datos para '$DB_USER'/'$DB_NAME'..."
    DB_PASS=$(python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24)))")

    sudo -u postgres psql -v ON_ERROR_STOP=1 <<-EOSQL
	DO \$\$
	BEGIN
	    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
	        CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';
	    ELSE
	        ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASS}';
	    END IF;
	END
	\$\$;
	SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
	WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\gexec
	EOSQL

    echo "[+] Escribiendo $ENV_FILE (permisos restringidos, dueño 'marandu')..."
    cat << ENVEOF > "$ENV_FILE"
DATABASE_URL=postgresql+asyncpg://${DB_USER}:${DB_PASS}@127.0.0.1:5432/${DB_NAME}
ENVEOF
    chmod 600 "$ENV_FILE"
    chown marandu:marandu "$ENV_FILE"
    unset DB_PASS
else
    echo "[ ] $ENV_FILE ya existe; no se regeneran credenciales de base de datos."
fi

# 6. Habilitar pgaudit si el módulo está instalado
PG_CONF=$(sudo -u postgres psql -tAc "SHOW config_file;" 2>/dev/null || true)
if [ -n "$PG_CONF" ] && [ -f "$PG_CONF" ] && ! grep -q "^shared_preload_libraries.*pgaudit" "$PG_CONF"; then
    echo "[+] Habilitando pgaudit en $PG_CONF..."
    {
        echo "shared_preload_libraries = 'pgaudit'"
        echo "pgaudit.log = 'write, ddl, role'"
    } >> "$PG_CONF"
    systemctl restart postgresql 2>/dev/null || systemctl restart postgresql-16 || true
fi

# 7. firewalld: requerido por ip_block / ip_rate_limit (usan la zona 'drop')
echo "[+] Habilitando firewalld..."
systemctl enable --now firewalld
if ! firewall-cmd --get-zones 2>/dev/null | grep -qw drop; then
    echo "[!] Advertencia: la zona 'drop' de firewalld no aparece disponible."
fi

# 8. auditd y sshd
echo "[+] Habilitando auditd y sshd..."
systemctl enable --now auditd
systemctl enable --now sshd

# 9. Ajustar la propiedad y permisos del directorio del proyecto
# (al final, para no pisar el chmod 600 del .env con el chmod recursivo)
echo "[+] Aplicando propiedad a $PROJ_DIR..."
chown -R marandu:marandu "$PROJ_DIR"
chmod -R 750 "$PROJ_DIR"
if [ -f "$ENV_FILE" ]; then
    chmod 600 "$ENV_FILE"
    chown marandu:marandu "$ENV_FILE"
fi

echo "=============================================================================="
echo "[✓] Configuración finalizada."
echo "Para continuar con la instalación web (venv + tablas + seed de configuracion_modulos), ejecuta:"
echo "    sudo -u marandu ./setup_web.sh"
echo "=============================================================================="