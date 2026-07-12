# M.A.R.A.N.D.U.
### Malicious Attack Response, Analysis, and Network Detection Unit

Sistema de Prevención de Intrusiones basado en Host (HIPS) desarrollado como
Trabajo Práctico N°2 para la materia **Sistemas Operativos 2**.

El sistema corre sobre **Rocky Linux** (última versión estable) e integra
módulos de detección, prevención automatizada y un dashboard web de alertas
en tiempo real.

---

## 🎯 Objetivos del sistema

- Detectar y responder automáticamente a amenazas a nivel de host (integridad
  de archivos, sniffers, fuerza bruta, procesos maliciosos, ataques DDoS, etc.)
- Registrar todas las alarmas en `/var/log/hips/` con formato estandarizado
- Notificar al administrador por email ante cada evento de seguridad
- Proveer una interfaz web protegida con login para configuración y monitoreo
- Aplicar al menos 10 controles de hardening sobre Rocky Linux y 7 sobre
  PostgreSQL (CIS Benchmark)

---

## 👥 Integrantes

| Nombre               | Legajo   | Rol principal                        |
|----------------------|----------|--------------------------------------|
| [Integrante 1]       | XXXXXX   | Módulos de detección + BD            |
| [Integrante 2]       | XXXXXX   | Interfaz web + Módulo de prevención  |

---

## 🛠️ Stack Tecnológico

| Componente         | Tecnología                              | Justificación                                                  |
|--------------------|-----------------------------------------|----------------------------------------------------------------|
| Lenguaje principal | Python 3.x                              | Ecosistema completo para syscalls, logs y scripting de SO      |
| Framework web      | FastAPI                                 | Async nativo, validación automática, docs Swagger integradas   |
| Base de datos      | PostgreSQL                              | Requerimiento obligatorio de la cátedra                        |
| Conector BD        | psycopg2 / SQLAlchemy                   | ORM estándar con soporte async                                 |
| Llamadas al SO     | subprocess + psutil + os                | Interacción directa con procesos, red y sistema de archivos    |
| Alertas email      | smtplib (stdlib)                        | Sin dependencias externas para envío de notificaciones         |
| Testing            | pytest                                  | Framework de testing automatizado estándar en Python           |
| Hardening OS       | SELinux, firewalld, auditd, SSH, etc.   | CIS Benchmark for Rocky Linux                                  |
| Hardening BD       | CIS PostgreSQL Benchmark (7 controles) | Seguridad en capa de datos                                     |

---

## 📁 Estructura del Proyecto
MARANDU/
├── detection/          # Módulos de detección i–x
├── prevention/         # Acciones de prevención automatizada
├── alerts/             # Logger central y notificaciones email
├── web/                # Aplicación FastAPI + templates
├── db/                 # Modelos y migraciones PostgreSQL
├── config/             # Configuración encriptada (no commitear .env real)
├── tests/              # Tests automatizados con pytest
├── docs/               # Manual de usuario e instalación
├── .env.example        # Template de variables de entorno
└── requirements.txt    # Dependencias Python

---
## Requisitos del Sistema Operativo
Antes de ejecutar el HIPS, asegúrese de instalar las dependencias nativas en Rocky Linux:

```bash
sudo dnf install -y policycoreutils-python-utils audit audit-rules firewalld rsyslog openssl python3-devel gcc authselect pgaudit_16 acl
```
---

## ⚙️ Instalación rápida

```bash
# Clonar el repositorio
git clone https://github.com/usuario/MARANDU.git
cd MARANDU

# Crear entorno virtual e instalar dependencias
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con los valores reales

# Iniciar el servidor web
uvicorn web.app:app --host 0.0.0.0 --port 8000
```

---

## 🔒 Hardening de Base de Datos (PostgreSQL)

El sistema incluye una suite de hardening para PostgreSQL basada en el estándar CIS.

### Aplicación del Hardening
Para aplicar automáticamente los 7 controles de seguridad sobre la base de datos (incluyendo TLS, roles, privilegios y auditoría), ejecuta:

```bash
sudo python3 prevention/db_auth.py -p <TU_CONTRASEÑA> -d <TU_BD> -u postgres
```

---
## Verificación de Cumplimiento (Checker)
Para auditar que los controles se mantienen activos y configurados correctamente, utiliza la herramienta de verificación:

```bash
sudo -u postgres python3 tests/db_hardening_check.py -d <TU_BD> -u postgres -H 127.0.0.1 -p <TU_CONTRASEÑA>
```
Si todos los controles están correctos, el script mostrará [+] COMPLIANCE OK.
---

---

## 📋 Módulos de Detección

| #    | Módulo                         | Archivo                   |
|------|--------------------------------|---------------------------|
| i    | Integridad de archivos         | `detection/file_integrity.py`  |
| ii   | Usuarios conectados            | `detection/users_monitor.py`   |
| iii  | Sniffers y modo promiscuo      | `detection/sniffer_detect.py`  |
| iv   | Análisis de logs               | `detection/log_analyzer.py`    |
| v    | Cola de correo / spam masivo   | `detection/mail_queue.py`      |
| vi   | Procesos con alto consumo      | `detection/process_monitor.py` |
| vii  | Directorio /tmp sospechoso     | `detection/tmp_monitor.py`     |
| viii | Ataques DDoS                   | `detection/ddos_detect.py`     |
| ix   | Archivos cron sospechosos      | `detection/cron_monitor.py`    |
| x    | Intentos de acceso inválidos   | `detection/access_monitor.py`  |

---

## 📄 Licencia

Proyecto académico — Sistemas Operativos 2 · 2026
