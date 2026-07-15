#!/bin/bash
# ==============================================================================
# M.A.R.A.N.D.U. - Fase 1: Configuración del Entorno Base (Hardening de DB)
# ==============================================================================
set -e

# Asegurar que se ejecuta con privilegios de root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Error: Este script debe ser ejecutado como root o usando sudo."
    exit 1
fi

PROJ_DIR=$(pwd)
ENV_FILE="$PROJ_DIR/.env"
VENV_DIR="$PROJ_DIR/venv"
PREVENTION_DIR="$PROJ_DIR/prevention"
DETECTION_DIR="$PROJ_DIR/detection"

echo "=============================================================================="
echo "[+] Iniciando configuración de seguridad de Base de Datos para M.A.R.A.N.D.U..."
echo "    Directorio del proyecto detectado: $PROJ_DIR"
echo "=============================================================================="

# 1. Solicitar contraseñas de Base de Datos de forma segura
echo "--- CONFIGURACIÓN DE CREDENCIALES DE POSTGRESQL (CIS) ---"
read -sp "[?] Define una contraseña para el superusuario DB 'postgres': " PG_PASS
echo ""
read -sp "[?] Define una contraseña para el usuario limitado DB 'marandu_app': " DB_PASS
echo ""
echo "------------------------------------------------------------"

if [ -z "$PG_PASS" ] || [ -z "$DB_PASS" ]; then
    echo "[!] Error: Las contraseñas no pueden estar vacías."
    exit 1
fi

# 2. Instalación de dependencias del sistema[cite: 4]
echo "[+] Instalando dependencias del sistema..."
dnf install -y python3 python3-pip openssh-server audit firewalld nginx postgresql-server postgresql-contrib postgresql-devel pgaudit gcc python3-devel

# 3. Inicializar PostgreSQL si es un servidor nuevo[cite: 4]
if [ ! -d "/var/lib/pgsql/data" ] || [ -z "$(ls -A /var/lib/pgsql/data)" ]; then
    echo "[+] Inicializando base de datos PostgreSQL..."
    postgresql-setup --initdb
else
    echo "[ ] PostgreSQL ya está inicializado."
fi

# Habilitar pgaudit (Control de auditoría CIS)[cite: 4]
PG_CONF="/var/lib/pgsql/data/postgresql.conf"
if ! grep -q "pgaudit" "$PG_CONF"; then
    echo "[+] Habilitando pgaudit en $PG_CONF..."
    echo "shared_preload_libraries = 'pgaudit'" >> "$PG_CONF"
    echo "pgaudit.log = 'all, -misc'" >> "$PG_CONF"
fi

# Iniciar y habilitar PostgreSQL[cite: 4]
systemctl enable --now postgresql

# 4. Asignar contraseña al superusuario 'postgres' de la base de datos (Hardening)
echo "[+] Asegurando la cuenta del superusuario de base de datos 'postgres'..."
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '$PG_PASS';"

# 5. Crear el usuario limitado 'marandu_app' y la base de datos (Sin SUPERUSER ni CREATEDB)
echo "[+] Creando el rol dedicado y restringido 'marandu_app'..."
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='marandu_app'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER marandu_app WITH NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$DB_PASS';"

# Crear la base de datos asignando a nuestro usuario limitado como dueño
echo "[+] Creando la base de datos 'marandu' propiedad de 'marandu_app'..."
sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw marandu || \
    sudo -u postgres psql -c "CREATE DATABASE marandu OWNER marandu_app;"

# 6. Revocar privilegios públicos por defecto en el esquema public (Hardening CIS de Postgres)
echo "[+] Aplicando hardening sobre el esquema público..."
sudo -u postgres psql -d marandu -c "REVOKE ALL ON SCHEMA public FROM PUBLIC;"
sudo -u postgres psql -d marandu -c "GRANT ALL ON SCHEMA public TO marandu_app;"

# 7. Crear/actualizar el archivo .env apuntando al usuario limitado
echo "[+] Generando archivo .env con credenciales restringidas..."
cat <<EOF > "$ENV_FILE"
# Configuración de Base de Datos Restringida para M.A.R.A.N.D.U
DB_USER=marandu_app
DB_PASSWORD=$DB_PASS
DB_NAME=marandu
DB_HOST=127.0.0.1
DB_PORT=5432
EOF

# Permisos del archivo de configuración (Solo lectura para el dueño y su grupo)
chmod 640 "$ENV_FILE"

# 8. Crear el usuario del sistema 'marandu' para ejecutar el servicio si no existe (SIN tocar su contraseña)[cite: 4]
if ! id "marandu" &>/dev/null; then
    echo "[+] Creando usuario de sistema 'marandu'..."
    useradd -m -s /bin/bash marandu
else
    echo "[ ] El usuario 'marandu' ya existe en el sistema."
fi

# 9. Configurar sudoers para las acciones del HIPS[cite: 4]
# NOTA: VENV_DIR y PREVENTION_DIR se calculan a partir de PROJ_DIR (pwd al ejecutar este
# script), así que las rutas quedan correctas para la instalación actual sin hardcodear nada.
# El venv todavía no existe en este punto (lo crea setup_web.sh en Fase 2, como el usuario
# 'marandu'), pero sudoers no necesita que el binario exista al momento de escribir la regla,
# solo al momento de ejecutarla.
echo "[+] Configurando /etc/sudoers.d/marandu..."
mkdir -p /etc/sudoers.d
cat <<EOF > /etc/sudoers.d/marandu
# Generado automáticamente por setup_env.sh - $(date '+%Y-%m-%d %H:%M:%S')
# Proyecto: $PROJ_DIR
Defaults:marandu !requiretty

# --- Gestión del propio servicio ---
marandu ALL=(root) NOPASSWD: /usr/bin/systemctl restart marandu-web
marandu ALL=(root) NOPASSWD: /usr/bin/systemctl status marandu-web
marandu ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx
marandu ALL=(root) NOPASSWD: /usr/bin/firewall-cmd *

# --- Grupo A: scripts de hardening standalone (prevention/) ---
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/auditd.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/banner.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/firewall.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/pam_faillock.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/password_hardening.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/secure_tmp_mount.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/selinux.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/sysctl.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/ssh_hardening.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/ssh_hardening.py *
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/rsyslog_centralization.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $PREVENTION_DIR/db_auth.py -p * -d * -u *
marandu ALL=(root) NOPASSWD: /usr/sbin/sshd -T
marandu ALL=(root) NOPASSWD: /usr/bin/auditctl -l
marandu ALL=(root) NOPASSWD: /usr/sbin/auditctl -l

# Permitir al usuario marandu ejecutar los monitores específicos como root sin password
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $DETECTION_DIR/file_integrity_monitor.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $DETECTION_DIR/cron_monitor.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $DETECTION_DIR/ddos_detector.py
marandu ALL=(root) NOPASSWD: $VENV_DIR/bin/python3 $DETECTION_DIR/sniffer_detect.py

# --- Grupo C: comandos puntuales de mitigation_actions.py ---
marandu ALL=(root) NOPASSWD: /usr/bin/firewall-cmd --permanent --zone=drop --add-source=*
marandu ALL=(root) NOPASSWD: /usr/bin/firewall-cmd --permanent --zone=drop --add-rich-rule=*
marandu ALL=(root) NOPASSWD: /usr/bin/firewall-cmd --reload
marandu ALL=(root) NOPASSWD: /usr/sbin/chpasswd
marandu ALL=(root) NOPASSWD: /usr/sbin/usermod -L *
marandu ALL=(root) NOPASSWD: /usr/bin/dnf remove -y tcpdump
marandu ALL=(root) NOPASSWD: /usr/bin/dnf remove -y wireshark
marandu ALL=(root) NOPASSWD: /usr/bin/dnf remove -y wireshark-cli
marandu ALL=(root) NOPASSWD: /usr/bin/systemctl stop sshd
marandu ALL=(root) NOPASSWD: /usr/bin/systemctl stop crond
marandu ALL=(root) NOPASSWD: /usr/bin/systemctl stop postfix    

# --- Grupo B: kill / renice / cuarentena (mitigation_actions.py refactorizado a subprocess) ---
marandu ALL=(root) NOPASSWD: /usr/bin/kill -9 *
marandu ALL=(root) NOPASSWD: /usr/bin/renice -n * -p *
marandu ALL=(root) NOPASSWD: /usr/bin/mv * /var/lib/hips/quarantine/*
marandu ALL=(root) NOPASSWD: /usr/bin/chmod 000 /var/lib/hips/quarantine/*
EOF
chmod 440 /etc/sudoers.d/marandu

echo "[*] Validando sintaxis del archivo sudoers recién generado..."
if visudo -c -f /etc/sudoers.d/marandu; then
    echo "[+] Sintaxis de sudoers válida."
else
    echo "❌ Error: la sintaxis de /etc/sudoers.d/marandu es inválida. Revertir manualmente."
    exit 1
fi

# 10. Configurar Nginx como Proxy Inverso[cite: 4]
echo "[+] Configurando Nginx..."
cat <<EOF > /etc/nginx/conf.d/marandu.conf
server {
    listen 80;
    server_name localhost;

    access_log /var/log/nginx/marandu_access.log;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

# Crear el log de acceso con anticipación (si no existe) y aplicar ACLs
echo "[+] Configurando permisos ACL para que 'marandu' lea los logs de Nginx..."
touch /var/log/nginx/marandu_access.log
chown nginx:adm /var/log/nginx/marandu_access.log

# Aplicar ACL de lectura en el archivo y acceso/ejecución al directorio padre
setfacl -m u:marandu:rx /var/log/nginx
setfacl -m u:marandu:r /var/log/nginx/marandu_access.log

# Configurar persistencia de la ACL mediante logrotate
echo "[+] Asegurando persistencia de permisos tras rotación de logs..."
if [ -f "/etc/logrotate.d/nginx" ]; then
    # Insertar la regla de setfacl en el bloque postrotate existente de logrotate
    if ! grep -q "setfacl -m u:marandu" /etc/logrotate.d/nginx; then
        sed -i '/postrotate/a \        /usr/bin/setfacl -m u:marandu:r /var/log/nginx/marandu_access.log' /etc/logrotate.d/nginx
    fi
fi

# 11. Cortafuegos (firewalld)[cite: 4]
echo "[+] Configurando reglas de firewalld..."
systemctl enable --now firewalld
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload

# 12. Auditoría[cite: 4]
echo "[+] Habilitando auditd y sshd..."
systemctl enable --now auditd
systemctl enable --now sshd

# 13. Ajustar la propiedad del directorio del proyecto[cite: 4]
echo "[+] Aplicando propiedad a $PROJ_DIR..."
chown -R marandu:marandu "$PROJ_DIR"

echo "=============================================================================="
echo "[✓] CONFIGURACIÓN DE BASE DE DATOS Y ENTORNO TERMINADA."
echo "La base de datos ya está protegida con un rol limitado sin superusuario."
echo "El usuario 'marandu' ya tiene los permisos sudo mínimos necesarios para"
echo "ejecutar los módulos de hardening y reacción sin ser root."
echo "Para levantar el sitio, corre la Fase 2 como el usuario 'marandu':"
echo "    sudo -u marandu ./setup_web.sh"
echo "=============================================================================="