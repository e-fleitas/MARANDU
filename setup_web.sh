#!/bin/bash
# ==============================================================================
# M.A.R.A.N.D.U. - Fase 2: Configuración de la App, Base de Datos y Servicio
# ==============================================================================
set -e

# Validar de forma estricta que no se esté ejecutando como root accidentalmente[cite: 5]
if [ "$USER" != "marandu" ]; then
    echo "[!] Error de seguridad: Este script debe ser ejecutado exclusivamente por el usuario 'marandu'."
    echo "    Por favor usa: sudo -u marandu ./setup_web.sh [contraseña_db]"
    exit 1
fi

PROJ_DIR=$(pwd)
VENV_DIR="$PROJ_DIR/venv"
REQ_FILE="$PROJ_DIR/web/requirements.txt"

# Capturar la contraseña de la base de datos
DB_PASS="$1"

# Si no se pasó como parámetro de consola, pedirla interactivamente de forma segura
if [ -z "$DB_PASS" ]; then
    echo "--- AUTENTICACIÓN DE BASE DE DATOS (Fase 2) ---"
    read -sp "[?] Ingresa la contraseña del usuario DB 'marandu_app' para configurar el servicio: " DB_PASS
    echo ""
    echo "------------------------------------------------"
fi

if [ -z "$DB_PASS" ]; then
    echo "[!] Error: Se requiere la contraseña de la base de datos para continuar."
    exit 1
fi

echo "=============================================================================="
echo "[+] Iniciando configuración del entorno virtual para la interfaz de M.A.R.A.N.D.U..."
echo "=============================================================================="

# 1. Crear el entorno virtual si no existe[cite: 5]
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creando entorno virtual aislado (venv) en $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "[ ] El entorno virtual ya se encuentra inicializado."
fi

# 2. Activar el entorno e instalar dependencias[cite: 5]
echo "[+] Activando entorno virtual..."
source "$VENV_DIR/bin/activate"

echo "[+] Actualizando pip..."
pip install --upgrade pip

# 3. Instalación de dependencias de Python (Protegido contra el bug de db_writer)[cite: 5]
if [ -f "$REQ_FILE" ]; then
    echo "[+] Limpiando dependencias locales conflictivas en requirements.txt..."
    # Eliminar cualquier referencia a 'db_writer' temporalmente para que pip no falle
    sed -i '/db_writer/d' "$REQ_FILE"
    
    echo "[+] Instalando dependencias desde $REQ_FILE..."
    pip install -r "$REQ_FILE"
else
    echo "[!] Advertencia: No se detectó requirements.txt. Instalando stack base..."
    pip install fastapi uvicorn pydantic jinja2 python-multipart itsdangerous python-dotenv psycopg2-binary sqlalchemy asyncpg psutil passlib bcrypt
fi

# Asegurar módulos para bases de datos asíncronas
pip install "sqlalchemy[asyncio]" asyncpg python-dotenv

# 4. Crear tablas y correr el Seed de Configuración (Idempotente)[cite: 5]
# Exportamos temporalmente la variable para que seed_config.py sepa conectarse sin .env ni preguntar de nuevo
export DB_PASSWORD="$DB_PASS"
echo "[+] Preparando la base de datos (tablas + configuración inicial)..."
python -m db.seed_config
unset DB_PASSWORD

# 5. SOLUCIÓN AL ERROR DE PERMISOS (Paso crítico antes de configurar Systemd)[cite: 5]
echo "[+] Corrigiendo permisos físicos y contextos de SELinux para el servicio..."

# Nota: Como quitamos el archivo .env físico, ya no necesitamos cambiar sus permisos de disco.
# Aplicar las etiquetas requeridas de SELinux para que Systemd pueda operar desde /home
# Nota: Usamos 'sudo' ya que estas operaciones del kernel de seguridad requieren privilegios elevados.[cite: 5]
sudo chcon -R -t bin_t "$VENV_DIR/bin/"

# 6. Crear el archivo de servicio de Systemd (Inyectando variables seguras de entorno)[cite: 5]
echo "[+] Creando servicio de sistema (marandu-web.service)..."
sudo tee /etc/systemd/system/marandu-web.service > /dev/null <<EOF
[Unit]
Description=M.A.R.A.N.D.U. Interfaz Web (Uvicorn)
After=network.target postgresql.service

[Service]
User=marandu
Group=marandu
WorkingDirectory=$PROJ_DIR
# Pasamos las credenciales de forma segura al entorno del proceso sin leer un archivo .env
Environment="DB_USER=marandu_app"
Environment="DB_PASSWORD=$DB_PASS"
Environment="DB_NAME=marandu"
Environment="DB_HOST=127.0.0.1"
Environment="DB_PORT=5432"
ExecStart=$VENV_DIR/bin/uvicorn web.app:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 7. Recargar systemd y arrancar la aplicación[cite: 5]
echo "[+] Levantando y habilitando servicios..."
sudo systemctl daemon-reload
sudo systemctl enable --now marandu-web.service
sudo systemctl restart nginx.service
sudo systemctl enable nginx.service

# 8. Instalar el cron del DISPATCHER de mitigación (prevention/mitigation_actions.py)
#
# Los resolvedores por tipo_alarma (DISPATCH) y la exclusión de niveles
# (prevention/strategia.py) ya están implementados y listos: lo único que
# faltaba era ALGO que llame periódicamente a procesar_alarmas_pendientes()
# para que cada alarma con resuelta=False dispare su acción automáticamente.
# Este cron corre como 'marandu' (sin sudo, mitigation_actions.py invoca sudo
# -n internamente solo para los comandos puntuales que sí lo requieren).
#
# Se instala de forma idempotente: si ya existe una línea con el marcador
# MARANDU_MITIGACION, no se duplica (permite re-correr este script sin
# ensuciar el crontab).
# mitigation_actions.py (a diferencia de app.py) NO llama a load_dotenv():
# solo lee variables ya presentes en el entorno del proceso. Si no exporta
# DB_PASSWORD, db.session cae a un prompt interactivo -- y cron no tiene
# terminal ni stdin, así que ese prompt cuelga el proceso indefinidamente
# en vez de fallar. Por eso el cron carga explícitamente el .env del
# proyecto (set -a / source / set +a) antes de invocar el módulo.
echo "[+] Instalando cron del dispatcher de mitigación de alarmas..."
CRON_MARCADOR="MARANDU_MITIGACION"
CRON_LINEA="* * * * * /bin/bash -lc 'cd $PROJ_DIR && set -a && source $PROJ_DIR/.env && set +a && $VENV_DIR/bin/python3 -m prevention.mitigation_actions' >> /var/log/hips/mitigacion_cron.log 2>&1 # $CRON_MARCADOR"

( crontab -l 2>/dev/null | grep -v "$CRON_MARCADOR" ; echo "$CRON_LINEA" ) | crontab -
echo "[+] Cron instalado: el dispatcher de mitigación corre cada minuto, cargando .env antes de ejecutar."

echo "=============================================================================="
echo "[✓] PROCESO DE INSTALACIÓN COMPLETADO CON ÉXITO."
echo "La base de datos y sus módulos de mitigación están sembrados de forma segura."
echo "Puedes acceder al panel del HIPS M.A.R.A.N.D.U. en:"
echo "    http://localhost"
echo "=============================================================================="