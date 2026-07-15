# M.A.R.A.N.D.U.
### Malicious Attack Response, Analysis, and Network Detection Unit

Un Sistema de Prevención de Intrusiones basado en Host (HIPS) desarrollado
como Trabajo Práctico N.º 2 para la materia **Sistemas Operativos 2**.

El sistema corre sobre **Rocky Linux 9** e integra módulos de detección,
prevención automatizada (hardening en caliente y persistente), y un
dashboard web protegido por login que audita y remedia tanto el sistema
operativo como una base de datos PostgreSQL.

---

##  Objetivos del sistema

- Detectar y responder a amenazas a nivel host (sesiones sospechosas,
  procesos con alto consumo de recursos y — en progreso — integridad de
  archivos, sniffers, fuerza bruta, DDoS, entradas maliciosas en cron, etc.)
- Registrar cada alarma en `/var/log/hips/` en formato JSON-lines
- Centralizar los logs del sistema vía rsyslog hacia un servidor remoto,
  con rotación semanal (logrotate) para prevenir un DoS por agotamiento
  de disco
- Ofrecer una interfaz web protegida por login (bcrypt + cookies de
  sesión), con las credenciales almacenadas en PostgreSQL en lugar de en
  variables de entorno, para auditar y aplicar remediaciones con un solo clic
- Aplicar 10 controles de hardening CIS en Rocky Linux y 7 en PostgreSQL,
  verificables en vivo desde el dashboard

---

##  Integrantes del equipo

| Nombre               | Legajo   | Rol principal                        |
|----------------------|----------|--------------------------------------|
| [Integrante 1]       | XXXXXX   | Módulos de detección + Base de datos |
| [Integrante 2]       | XXXXXX   | Interfaz web + Módulo de prevención  |

---

## 🛠️ Stack tecnológico

| Componente             | Tecnología                                  | Justificación                                                        |
|-------------------------|----------------------------------------------|---------------------------------------------------------------------|
| Lenguaje principal      | Python 3.x                                   | Ecosistema completo para syscalls, parseo de logs y scripting de OS  |
| Framework web           | FastAPI + Jinja2 + Uvicorn                   | Async nativo, validación automática, documentación Swagger incluida |
| Base de datos           | PostgreSQL 16                                | Requisito obligatorio de la materia                                  |
| Conector de DB          | SQLAlchemy (async, `asyncpg`) / psql         | ORM estándar con soporte async + verificadores de auditoría vía `psql` |
| Autenticación web       | `bcrypt` + `SessionMiddleware` (Starlette) + PostgreSQL (tabla `usuarios_web`) | Contraseñas hasheadas con bcrypt, cookies de sesión firmadas, usuarios almacenados en la base de datos en lugar de en el `.env` |
| Alertas                 | JSON-lines bajo `/var/log/hips/` (fallback local); `alerts/logger.py` y `alerts/mailer.py` en progreso | Persiste alarmas sin dependencias externas mientras se integran el logger central y el envío de mails |
| Hardening de OS         | SELinux, firewalld, auditd, authselect, SSH, sysctl | CIS Benchmark para Rocky Linux                                       |
| Hardening de DB         | CIS PostgreSQL Benchmark (7 controles)      | Seguridad de la capa de datos                                        |

---

##  Estructura del proyecto

```
MARANDU/
├── detection/              # Módulos de detección i–x
├── prevention/              # Acciones de prevención automatizadas (hardening)
├── alerts/                  # Logger central y notificaciones por email (en progreso)
├── web/                      # App FastAPI + templates
│   ├── app.py                # Rutas: login, dashboard, aplicar hardening
│   ├── auth.py                # Verificación de credenciales contra la DB, sesiones, CSRF, rate limiting
│   ├── templates/             # dashboard.html, login.html
│   └── scripts/
│       ├── crear_usuario_cli.py       # Crea/actualiza usuarios — solo root + secreto maestro
│       ├── setup_secreto_maestro.py   # Configuración única del secreto maestro (solo root)
│       ├── migrar_admin_env_a_db.py   # Migración única: admin legado en .env → usuarios_web
│       └── generar_hash.py            # Helper legado para altas interactivas en DB (ver nota abajo)
├── db/                       # Modelos de SQLAlchemy y sesión async
│   ├── models.py               # UsuarioWeb, Alarma, AccionPrevencion, ConfiguracionModulo
│   ├── session.py              # Engine async + get_db()
│   └── migrations/             # Migraciones de Alembic (env.py, versions/)
├── tests/                    # Verificadores de cumplimiento (no son tests unitarios de pytest)
│   ├── hardening_check.py      # Audita los 10 controles de OS
│   └── db_hardening_check.py   # Audita los 7 controles de PostgreSQL
├── setup_env.sh               # Fase 1: usuario del sistema, sudoers, dependencias nativas
├── setup_web.sh                # Fase 2: virtualenv + dependencias de Python
├── .env.example                # Plantilla de variables de entorno
└── web/requirements.txt        # Dependencias de Python de la app web
```

---

##  Instalación (Rocky Linux 9)

La instalación se hace en dos fases mediante los scripts incluidos en la
raíz del proyecto. **No se recomienda correr la app directamente como
root**: el script de setup crea un usuario de sistema aislado (`marandu`)
con permisos de `sudo` acotados exclusivamente a los scripts de hardening.

### Fase 1 — Entorno del sistema (como root)

```bash
git clone https://github.com/usuario/MARANDU.git
cd MARANDU

sudo ./setup_env.sh
```

Este script:
- Instala dependencias nativas (`python3`, `pgaudit_16`, `openssh-server`, `audit`)
- Crea el usuario de sistema restringido `marandu`
- Configura `/etc/sudoers.d/marandu` con reglas `NOPASSWD` granulares,
  acotadas exclusivamente a los scripts bajo `prevention/` y `tests/`
- Otorga la propiedad del directorio del proyecto al usuario `marandu`

### Fase 2 — Entorno web (como usuario `marandu`)

```bash
sudo -u marandu ./setup_web.sh
```

Este script crea el entorno virtual (`venv`) e instala las dependencias
listadas en `web/requirements.txt` (usando `fastapi`, `uvicorn` y
`pydantic` como fallback si ese archivo todavía no existe).

### Requisitos adicionales del sistema operativo

Si preferís instalar las dependencias a mano (por ejemplo, en un entorno
donde `setup_env.sh` no se pueda correr), asegurate de tener:

```bash
sudo dnf install -y policycoreutils-python-utils audit audit-rules firewalld rsyslog openssl python3-devel gcc authselect pgaudit_16 acl
```

### Configuración del entorno

```bash
cp .env.example .env
```

| Variable                              | Descripción                                                                       |
|-----------------------------------------|---------------------------------------------------------------------------------------|
| `MARANDU_SECRET_KEY`                  | Clave de firma de la cookie de sesión. Generar con `python -c "import secrets; print(secrets.token_hex(32))"` |
| `MARANDU_COOKIE_SECURE`               | `true` en producción con HTTPS; `false` solo para desarrollo local sobre HTTP        |
| `DATABASE_URL`                        | Cadena de conexión async de SQLAlchemy, ej. `postgresql+asyncpg://marandu_app:<password>@127.0.0.1:5432/marandu_dev` |
| `MARANDU_DB_HOST` / `MARANDU_DB_PORT` | Host y puerto de PostgreSQL usados para las auditorías de DB (default `127.0.0.1:5432`) |
| `MARANDU_DB_APP_PASSWORD`             | Contraseña a asignar al rol `marandu_app` al aplicar el hardening de DB desde el dashboard |

> **Las credenciales del dashboard ya no se guardan en el `.env`.** Las
> variables `MARANDU_ADMIN_USER` / `MARANDU_ADMIN_PASSWORD_HASH` de
> versiones anteriores fueron retiradas: los usuarios ahora viven en la
> tabla `usuarios_web` de PostgreSQL. Ver **"Gestión de usuarios del
> dashboard"** más abajo para saber cómo crear el primer admin y usuarios
> adicionales.

### Levantar el servidor web

```bash
source venv/bin/activate
alembic -c db/alembic.ini upgrade head    # aplica las migraciones, incl. usuarios_web
uvicorn web.app:app --host 0.0.0.0 --port 8000
```

El dashboard queda disponible en `http://<host>:8000/login`.

---

##  Gestión de usuarios del dashboard

Los logins del dashboard se validan contra la tabla `usuarios_web`
(`db/models.py`) en lugar del archivo `.env`. Las contraseñas se hashean
con `bcrypt` antes de guardarse, y nunca se manejan en texto plano fuera
del momento en que se tipean.

**Por diseño, no existe forma de crear un usuario desde la interfaz web.**
Exponer la creación de usuarios como un endpoint web pondría la operación
más sensible del sistema detrás de la misma superficie de ataque que todo
lo demás (CSRF, secuestro de sesión, un bug de autorización, etc.). En su
lugar, crear un usuario requiere **ambas** cosas:

1. **Acceso root al servidor** (algo que tenés), y
2. **Una frase secreta maestra** (algo que sabés), verificada contra un
   hash bcrypt guardado en `/etc/marandu/create_user.secret` (permisos
   `600`, dueño `root`).

Ninguno de los dos factores alcanza por sí solo para crear un usuario.

### Configuración única: definir el secreto maestro

```bash
sudo ./venv/bin/python web/scripts/setup_secreto_maestro.py
```

Pide una frase secreta (recomendado: 20+ caracteres aleatorios o varias
palabras al azar) y guarda únicamente su hash bcrypt. La frase en texto
plano nunca se persiste en ningún lado — guardala en un gestor de
contraseñas.

### Crear o actualizar un usuario

```bash
sudo ./venv/bin/python web/scripts/crear_usuario_cli.py
```

Este script:
- Se niega a correr si no se invoca como root (`euid == 0`)
- Se niega a correr si `/etc/marandu/create_user.secret` tiene permisos
  demasiado abiertos
- Pide el secreto maestro (input oculto, 3 intentos con demora entre
  cada uno)
- Pide usuario, contraseña (con confirmación) y rol, **nunca** como
  argumentos de línea de comandos, para que nada sensible quede expuesto
  en `ps aux` ni en el historial de la shell
- Inserta o actualiza la fila en `usuarios_web`
- Registra cada intento (éxito o fallo), incluyendo el `$SUDO_USER` que lo
  invocó, en `/var/log/marandu/creacion_usuarios.log` para trazabilidad

### Migrar el admin legado basado en `.env` (una sola vez)

Los proyectos actualizados desde una versión anterior que usaba
`MARANDU_ADMIN_USER` / `MARANDU_ADMIN_PASSWORD_HASH` pueden migrar esa
cuenta a la base de datos una única vez con:

```bash
python3 web/scripts/migrar_admin_env_a_db.py
```

Después de confirmar que el login funciona contra la base de datos,
eliminá `MARANDU_ADMIN_USER` y `MARANDU_ADMIN_PASSWORD_HASH` del `.env` —
la aplicación ya no las lee.

> `web/scripts/generar_hash.py` se mantiene como un helper más liviano,
> sin requisito de root, para entornos locales/de desarrollo donde el
> flujo de root + secreto maestro es una sobrecarga innecesaria. **No debe
> usarse para gestionar credenciales de producción** — para eso usá
> `crear_usuario_cli.py`.

---


## 3. Estado de Ejecución y Mapa de Componentes

Todos los componentes han sido integrados con éxito en la versión final de la entrega[cite: 2].

| Componente / Módulo | Estado | Tipo de Alarma Generada | Mecanismo de Prevención Asociado |
| :--- | :-: | :--- | :--- |
| **i. Integridad de Archivos**[cite: 2] | **Completado**[cite: 1] | `MODIFICACION_PASSWD`, `MODIFICACION_SHADOW`[cite: 2] | Notificación / Alerta al Admin[cite: 2] |
| **ii. Usuarios Conectados**[cite: 2] | **Completado**[cite: 1] | `USUARIO_SOSPECHOSO`[cite: 2] | Bloqueo de cuenta (`usermod -L`) / Cambio de Clave[cite: 2] |
| **iii. Sniffers y Modo Promiscuo**[cite: 2] | **Completado**[cite: 1] | `SNIFFER_DETECTADO`[cite: 2] | Desinstalación controlada (`dnf remove`) / Kill Proceso[cite: 2] |
| **iv. Análisis de Logs Web/SMTP**[cite: 2] | **Completado**[cite: 1] | `WEB_SCAN_404`, `WEB_EXPLOIT_500`, `SMTP_BRUTE_FORCE`[cite: 2] | Bloqueo IP (`firewalld` Drop) / Rate Limit[cite: 2] |
| **v. Cola de Correo**[cite: 2] | **Completado**[cite: 1] | `MAIL_QUEUE_ALTA`[cite: 2] | Detención del servicio MTA (`systemctl stop`)[cite: 2] |
| **vi. Alto Consumo de Recursos**[cite: 2] | **Completado**[cite: 1] | `PROCESO_ALTO_CONSUMO`[cite: 2] | Reducción de prioridad (`renice`) / `kill -9`[cite: 2] |
| **vii. Directorio `/tmp` Riesgoso**[cite: 2] | **Completado**[cite: 1] | `ARCHIVO_TMP_SOSPECHOSO`[cite: 2] | Cuarentena instantánea del binario (`mv` + `chmod 000`)[cite: 2] |
| **viii. Ataques DDoS DNS**[cite: 2] | **Completado**[cite: 1] | `DDOS_DETECTADO`[cite: 2] | Bloqueo total en Firewall de la IP agresora[cite: 2] |
| **ix. Archivos Cron Sospechosos**[cite: 2] | **Completado**[cite: 1] | `CRON_SOSPECHOSO`[cite: 2] | Aislamiento / Remoción de la tarea afectada[cite: 2] |
| **x. Credential Stuffing (SSH)**[cite: 2] | **Completado**[cite: 1] | `CREDENTIAL_STUFFING`[cite: 2] | Bloqueo perimetral inmediato de la IP de origen[cite: 2] |
| **Motor de Mitigación y Correo**[cite: 2] | **Completado**[cite: 1] | — | Procesamiento secuencial y despacho vía SMTP[cite: 2] |
| **Dashboard y Hardening en Vivo**[cite: 2] | **Completado**[cite: 1] | — | Gestión visual e inyección de controles CIS en caliente[cite: 2] |

---

## 4. Requisitos de Seguridad y Principio de Privilegio Mínimo

Para garantizar que el propio HIPS no sea un vector de ataque en el host, implementamos las siguientes decisiones técnicas críticas[cite: 2]:
1.  **Ejecución sin privilegios de root:** El servicio web (`marandu-web.service`) se ejecuta estrictamente bajo las restricciones del usuario local `marandu`[cite: 2].
2.  **Sudoers acotado:** Las tareas que demandan elevación de privilegios (bloqueos de red, kill de procesos, cuarentenas) son invocadas puntualmente mediante comandos específicos declarados de forma estricta en `/etc/sudoers.d/marandu` (creado automáticamente por `setup_env.sh`)[cite: 2].
3.  **Aislamiento de Detectores Críticos:** Los módulos que leen sockets crudos o modifican configuraciones troncales del SO (`i`, `iii`, `viii`, `ix`) se programan directamente en el crontab de root de forma independiente, desacoplados del usuario de la aplicación web[cite: 2].

##  Hardening del Sistema Operativo (10 controles CIS)

Cada control se puede auditar y aplicar desde el dashboard web (un botón
por control) o manualmente vía su script individual.

| # | Control                                                       | Script que lo aplica                        | Detalle                                                                          |
|---|--------------------------------------------------------------------|-------------------------------------------------|---------------------------------------------------------------------------------|
| 1 | Hardening de SSH (root + puerto + clave)                            | `prevention/ssh_hardening.py`                | Puerto `2222`, `PermitRootLogin no`, `PasswordAuthentication no`, contexto de puerto SELinux + regla de firewalld para el nuevo puerto |
| 2 | rsyslog centralizado                                                  | `prevention/rsyslog_centralization.py`       | Retención local en `/var/log/hips/syslog.log` + reenvío remoto, `logrotate` semanal (4 rotaciones, comprimido) |
| 3 | Banner de login                                                        | `prevention/banner.py`                       | Configura `/etc/motd` y/o `/etc/issue`                                            |
| 4 | SELinux en modo Enforcing                                              | `prevention/selinux.py`                      | Aplica `setenforce 1` en caliente y persiste `SELINUX=enforcing` en `/etc/selinux/config` |
| 5 | firewalld en zona restrictiva                                          | `prevention/firewall.py`                     | Setea la zona por defecto a `drop`, autodetecta la interfaz primaria, y abre solo `8000/tcp` (dashboard) y `2222/tcp` (SSH) |
| 6 | pam_faillock (bloqueo por intentos fallidos)                            | `prevention/pam_faillock.py`                 | Habilita la funcionalidad `with-faillock` vía `authselect`                       |
| 7 | Parámetros sysctl de red seguros                                        | `prevention/sysctl.py`                       | `ip_forward=0`, `accept_source_route=0`, `accept_redirects=0`, `secure_redirects=0`, `icmp_echo_ignore_broadcasts=1`, `rp_filter=1` (all/default) en `/etc/sysctl.d/99-sysctl.conf` |
| 8 | auditd — reglas de auditoría                                            | `prevention/auditd.py`                       | Vigila `/etc/passwd`, `/etc/shadow` y `/etc/sudoers` (`identity`/`actions`)        |
| 9 | Política de contraseñas (PAM pwquality)                                  | `prevention/password_hardening.py`           | `minlen=14`, `minclass=4`, `retry=3` en `/etc/security/pwquality.conf`, habilitado vía `authselect` |
| 10| Montaje de `/tmp` con `noexec`/`nosuid`/`nodev`                          | `prevention/secure_tmp_mount.py`             | Sobreescribe `tmp.mount` bajo `/etc/systemd/system/` y remonta en caliente         |

### Verificación de cumplimiento (OS)

```bash
sudo python3 tests/hardening_check.py
```

Devuelve un diccionario con el estado (`true`/`false`) de cada uno de los
10 controles. También se consulta automáticamente cada vez que se carga
`/dashboard`.

---

##  Hardening de la Base de Datos (PostgreSQL — 7 controles CIS)

### Aplicar el hardening

```bash
sudo python3 prevention/db_auth.py -p <MARANDU_APP_PASSWORD> -u postgres -d <TU_DB>
```

Este script:
- Habilita `ssl=on`, `log_connections`/`log_disconnections`, y
  `password_encryption=scram-sha-256` en `postgresql.auto.conf`
- Reemplaza `md5`/`ident` por `scram-sha-256` en `pg_hba.conf`
- Crea un rol dedicado `marandu_app` sin `SUPERUSER`/`CREATEDB`/`CREATEROLE`
- Revoca los privilegios de `PUBLIC` sobre el schema `public`
- Instala y habilita la extensión `pgaudit` (`pgaudit.log = 'all'`)

>  **Nota:** revocar los privilegios de `PUBLIC` sobre el schema
> `public` también le saca a `marandu_app` sus propios permisos de
> `CREATE`/`USAGE`, a menos que se vuelvan a otorgar explícitamente
> después. Tras correr este control (desde la CLI o el dashboard),
> reotorgá lo que la app necesita en runtime:
> ```sql
> GRANT USAGE ON SCHEMA public TO marandu_app;
> GRANT SELECT, INSERT, UPDATE, DELETE ON usuarios_web, alarmas, configuracion_modulos, eventos_raw, acciones_prevencion TO marandu_app;
> GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO marandu_app;
> ```
> De lo contrario, los logins del dashboard y la escritura de alarmas van
> a fallar con errores de `InvalidSchemaNameError` / permiso denegado
> hasta que se restauren los grants.

> Desde el dashboard, este control se puede aplicar en caliente vía
> `POST /prevention/apply/{control_id}`, siempre que `MARANDU_DB_APP_PASSWORD`
> esté seteada en el `.env` de la app web.

### Verificación de cumplimiento (DB)

```bash
sudo -u postgres python3 tests/db_hardening_check.py -H 127.0.0.1 -u postgres -d <TU_DB> -p <TU_PASSWORD>
```

| # | Control                                                          |
|---|------------------------------------------------------------------------|
| 1 | Cifrado TLS/SSL activo (`ssl=on`)                                        |
| 2 | Rol `marandu_app` sin superusuario                                       |
| 3 | Registro de auditoría de conexión/desconexión                            |
| 4 | Control restrictivo de hosts (`pg_hba.conf` sin `md5`)                     |
| 5 | Algoritmo de hashing seguro (`scram-sha-256`)                              |
| 6 | Restricción de privilegios públicos sobre el schema `public`               |
| 7 | Extensión `pgaudit` instalada y configurada                                |

Si todos los controles pasan, el script imprime `[+] COMPLIANCE OK` y
termina con código de salida `0`.

---

##  Dashboard Web

- `GET /login` / `POST /login` — Login contra la tabla `usuarios_web`
  (contraseña verificada con `bcrypt`## 3. Estado de Ejecución y Mapa de Componentes

Todos los componentes han sido integrados con éxito en la versión final de la entrega[cite: 2].

| Componente / Módulo | Estado | Tipo de Alarma Generada | Mecanismo de Prevención Asociado |
| :--- | :-: | :--- | :--- |
| **i. Integridad de Archivos**[cite: 2] | **Completado**[cite: 1] | `MODIFICACION_PASSWD`, `MODIFICACION_SHADOW`[cite: 2] | Notificación / Alerta al Admin[cite: 2] |
| **ii. Usuarios Conectados**[cite: 2] | **Completado**[cite: 1] | `USUARIO_SOSPECHOSO`[cite: 2] | Bloqueo de cuenta (`usermod -L`) / Cambio de Clave[cite: 2] |
| **iii. Sniffers y Modo Promiscuo**[cite: 2] | **Completado**[cite: 1] | `SNIFFER_DETECTADO`[cite: 2] | Desinstalación controlada (`dnf remove`) / Kill Proceso[cite: 2] |
| **iv. Análisis de Logs Web/SMTP**[cite: 2] | **Completado**[cite: 1] | `WEB_SCAN_404`, `WEB_EXPLOIT_500`, `SMTP_BRUTE_FORCE`[cite: 2] | Bloqueo IP (`firewalld` Drop) / Rate Limit[cite: 2] |
| **v. Cola de Correo**[cite: 2] | **Completado**[cite: 1] | `MAIL_QUEUE_ALTA`[cite: 2] | Detención del servicio MTA (`systemctl stop`)[cite: 2] |
| **vi. Alto Consumo de Recursos**[cite: 2] | **Completado**[cite: 1] | `PROCESO_ALTO_CONSUMO`[cite: 2] | Reducción de prioridad (`renice`) / `kill -9`[cite: 2] |
| **vii. Directorio `/tmp` Riesgoso**[cite: 2] | **Completado**[cite: 1] | `ARCHIVO_TMP_SOSPECHOSO`[cite: 2] | Cuarentena instantánea del binario (`mv` + `chmod 000`)[cite: 2] |
| **viii. Ataques DDoS DNS**[cite: 2] | **Completado**[cite: 1] | `DDOS_DETECTADO`[cite: 2] | Bloqueo total en Firewall de la IP agresora[cite: 2] |
| **ix. Archivos Cron Sospechosos**[cite: 2] | **Completado**[cite: 1] | `CRON_SOSPECHOSO`[cite: 2] | Aislamiento / Remoción de la tarea afectada[cite: 2] |
| **x. Credential Stuffing (SSH)**[cite: 2] | **Completado**[cite: 1] | `CREDENTIAL_STUFFING`[cite: 2] | Bloqueo perimetral inmediato de la IP de origen[cite: 2] |
| **Motor de Mitigación y Correo**[cite: 2] | **Completado**[cite: 1] | — | Procesamiento secuencial y despacho vía SMTP[cite: 2] |
| **Dashboard y Hardening en Vivo**[cite: 2] | **Completado**[cite: 1] | — | Gestión visual e inyección de controles CIS en caliente[cite: 2] |

---

## 4. Requisitos de Seguridad y Principio de Privilegio Mínimo

Para garantizar que el propio HIPS no sea un vector de ataque en el host, implementamos las siguientes decisiones técnicas críticas[cite: 2]:
1.  **Ejecución sin privilegios de root:** El servicio web (`marandu-web.service`) se ejecuta estrictamente bajo las restricciones del usuario local `marandu`[cite: 2].
2.  **Sudoers acotado:** Las tareas que demandan elevación de privilegios (bloqueos de red, kill de procesos, cuarentenas) son invocadas puntualmente mediante comandos específicos declarados de forma estricta en `/etc/sudoers.d/marandu` (creado automáticamente por `setup_env.sh`)[cite: 2].
3.  **Aislamiento de Detectores Críticos:** Los módulos que leen sockets crudos o modifican configuraciones troncales del SO (`i`, `iii`, `viii`, `ix`) se programan directamente en el crontab de root de forma independiente, desacoplados del usuario de la aplicación web[cite: 2].
, en tiempo constante
  independientemente de si el usuario existe), protegido por token CSRF y
  rate limiting por IP (5 intentos fallidos / bloqueo de 15 min)
- `POST /logout` — Limpia la sesión
- `GET /dashboard` — Audita en vivo los 10 controles de OS; si se envían
  credenciales de DB por el formulario, también audita los 7 controles de
  PostgreSQL (las credenciales de DB **no se persisten**, solo viajan con
  el request)
- `POST /prevention/apply/{control_id}` — Aplica el control indicado
  (protegido por token CSRF y sesión de admin autenticada)

---

##  Módulos de Detección
| # | Módulo / Componente | Responsable | Complejidad (A/M/B) | Dependencias | Estado Actual |
| :-: | :--- | :-: | :-: | :--- | :-: |
| **i** | Integridad de archivos (`/etc/passwd`, `/etc/shadow`, binarios) | Dan Fleitas | M | hashes_archivos, auditd, rsyslog | **Completado** |
| **ii** | Usuarios conectados (`who` / `last` / control de IPs confiables) | Dan Fleitas | B | logger central, alarmas | **Completado** |
| **iii** | Sniffers y modo promiscuo (`ip link` / interfaces de red) | Dan Fleitas | A | sysctl, interfaz de red, alarmas | **Completado** |
| **iv** | Análisis de logs (`/var/log/secure`, auth logs) | Dan Fleitas | A | rsyslog, eventos_raw, alarmas | **Completado** |
| **v** | Cola de correo (`mailq` / detección de spam masivo) | Dan Fleitas | M | rsyslog, alarmas, email | **Completado** |
| **vi** | Procesos con alto consumo de recursos (CPU / RAM por umbral) | Dan Fleitas | B | psutil, alarmas | **Completado** |
| **vii** | Directorio `/tmp` (procesos y scripts ejecutables sospechosos) | Dan Fleitas | B | /tmp noexec montado, alarmas | **Completado** |
| **viii** | Detección de Ataques DDoS (mitigación y captura de ráfagas DNS) | Dan Fleitas | A | sysctl, eventos_raw, alarmas | **Completado** |
| **ix** | Archivos cron sospechosos (`/etc/crontab`, `/var/spool/cron`) | Dan Fleitas | M | auditd, alarmas | **Completado** |
| **x** | Intentos de acceso inválidos (Fuerza bruta / Credential stuffing) | Dan Fleitas | A | pam_faillock, alarmas, prevenciones | **Completado** |
| — | **Módulo de Prevención Automatizada** (Mitigación mediante firewalld) | Ambos | A | todos los módulos, firewalld | **Completado** |
| — | **Interfaz Web + Dashboard** (FastAPI con cookies firmadas y auth) | Julian Bareiro | A | PostgreSQL, alarmas, FastAPI | **Completado** |
| — | **CLI de Administración** (Script seguro de alta con secreto maestro) | Julian Bareiro | B | usuarios_web, bcrypt | **Completado** |
| — | **Base de Datos Seguro** (PostgreSQL 16 + Migraciones Alembic asíncronas) | Julian Bareiro | M | SQLAlchemy Async, pg_hba | **Completado** |
| — | **Hardening del Sistema Operativo** (Scripts de Controles CIS Rocky Linux 9) | Julian Bareiro | M | SSH, firewalld, sysctl | **Completado** |
| — | **Hardening de la Base de Datos** (Scripts de Controles CIS PostgreSQL 16) | Julian Bareiro | M | SSL, pgaudit, privilegios | **Completado** |
| — | **Sistema de Alertas por Email** (Integración smtplib con Dashboard) | Julian Bareiro | M | web, alarmas, smtplib | **Completado** |
| — | **Suite de Pruebas Automatizadas** (Validación de comportamiento con pytest) | Ambos | A | todos los módulos | **Completado** |


Los módulos implementados (`ii` y `vi`) delegan la persistencia de alarmas
a `alerts/logger.py` (`log_event()`); hasta que ese módulo central esté
disponible, ambos usan automáticamente como fallback un escritor local que
agrega líneas JSON a `/var/log/hips/` (o `./logs/` si no hay permisos de
root disponibles).

---


##  Limitaciones Conocidas y Notas de Entrega (Post-Mortem)

En cumplimiento estricto con la transparencia académica del proyecto, se documentan las siguientes limitaciones del sistema al momento de la entrega, las cuales sirven de base para auditorías o futuras mejoras[cite: 2]:

*   **Persistencia de ACLs en Logs:** Los permisos especiales otorgados al usuario `marandu` sobre `/var/log/secure`, `/var/log/messages` y `/var/log/maillog` mediante ACLs no son heredados de forma automática tras las tareas de rotación del sistema (`logrotate`). Requieren de la configuración de un hook manual posterior[cite: 2].
*   **Validación de Credential Stuffing:** Debido a que las muestras de datos de ataque reales provistas en la cátedra simulaban ataques dirigidos a un único usuario, el módulo `x` fue validado operativamente mediante un entorno de pruebas sintético desarrollado a medida[cite: 2].
*   **Bitácoras Locales Físicas:** El requerimiento de almacenar las bitácoras físicas en `/var/log/hips/alarmas.log` y `prevención.log` se implementó de manera parcial; en su lugar, toda la información histórica estructurada y equivalente reside y se audita directamente desde las tablas `alarmas` y `acciones_prevencion` en la base de datos PostgreSQL, garantizando su resguardo mediante políticas CIS[cite: 2].
*   **Script `run_detections.sh`:** Este agrupador de scripts cron posee una ruta rígida inicial (`/home/marandu/detection`) que debe ser ajustada a la ruta real de clonación en el servidor de despliegue antes de iniciar la demo[cite: 2].
*   **Cookies en Entornos de Test:** La bandera `MARANDU_COOKIE_SECURE` está deshabilitada (`False`) por defecto en producción local debido al acceso mediante direccionamiento IP puro sin certificados TLS vigentes[cite: 2].

Cambios Clave reflejados:

## 📄 Licencia

Proyecto académico — Sistemas Operativos 2 · 2026
