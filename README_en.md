# M.A.R.A.N.D.U.
### Malicious Attack Response, Analysis, and Network Detection Unit

A Host-based Intrusion Prevention System (HIPS) developed as Practical
Assignment #2 for the **Operating Systems 2** course.

The system runs on **Rocky Linux 9** and integrates detection modules,
automated prevention (live and persistent hardening), and a login-protected
web dashboard that audits and remediates both the operating system and a
PostgreSQL database.

---

## 🎯 System Objectives

- Detect and respond to host-level threats (suspicious sessions,
  high-resource processes, and — in progress — file integrity, sniffers,
  brute force, DDoS, malicious cron entries, etc.)
- Log every alarm to `/var/log/hips/` in JSON-lines format
- Centralize system logs via rsyslog to a remote server, with weekly
  rotation (logrotate) to prevent disk-exhaustion DoS
- Provide a login-protected web interface (bcrypt + session cookies), with
  credentials stored in PostgreSQL rather than in environment variables, to
  audit and apply remediations with a single click
- Apply 10 CIS hardening controls on Rocky Linux and 7 on PostgreSQL,
  verifiable live from the dashboard

---

## 👥 Team Members

| Name                 | ID       | Primary Role                         |
|----------------------|----------|--------------------------------------|
| [Member 1]           | XXXXXX   | Detection modules + Database         |
| [Member 2]           | XXXXXX   | Web interface + Prevention module    |

---

## 🛠️ Technology Stack

| Component           | Technology                               | Justification                                                   |
|-----------------------|--------------------------------------------|---------------------------------------------------------------------|
| Main language        | Python 3.x                                 | Full ecosystem for syscalls, log parsing, and OS scripting        |
| Web framework         | FastAPI + Jinja2 + Uvicorn                 | Native async, automatic validation, built-in Swagger docs         |
| Database              | PostgreSQL 16                              | Mandatory course requirement                                      |
| DB connector          | SQLAlchemy (async, `asyncpg`) / psql       | Standard ORM with async support + `psql`-based auditing checkers   |
| Web authentication    | `bcrypt` + `SessionMiddleware` (Starlette) + PostgreSQL (`usuarios_web` table) | Passwords hashed with bcrypt, signed session cookies, users stored in the database instead of `.env` |
| Alerting              | JSON-lines under `/var/log/hips/` (local fallback); `alerts/logger.py` and `alerts/mailer.py` in progress | Persists alarms with no external dependencies while the central logger and email delivery are being integrated |
| OS Hardening          | SELinux, firewalld, auditd, authselect, SSH, sysctl | CIS Benchmark for Rocky Linux                                     |
| DB Hardening          | CIS PostgreSQL Benchmark (7 controls)     | Data layer security                                                |

---

## 📁 Project Structure

```
MARANDU/
├── detection/              # Detection modules i–x
├── prevention/              # Automated prevention actions (hardening)
├── alerts/                  # Central logger and email notifications (in progress)
├── web/                      # FastAPI app + templates
│   ├── app.py                # Routes: login, dashboard, apply hardening
│   ├── auth.py                # DB-backed credential verification, sessions, CSRF, rate limiting
│   ├── templates/             # dashboard.html, login.html
│   └── scripts/
│       ├── crear_usuario_cli.py       # Creates/updates users — root-only + master secret
│       ├── setup_secreto_maestro.py   # One-time setup of the master secret (root-only)
│       ├── migrar_admin_env_a_db.py   # One-time migration: legacy .env admin → usuarios_web
│       └── generar_hash.py            # Legacy helper kept for interactive DB upserts (see note below)
├── db/                       # SQLAlchemy models and async session
│   ├── models.py               # UsuarioWeb, Alarma, AccionPrevencion, ConfiguracionModulo
│   ├── session.py              # Async engine + get_db()
│   └── migrations/             # Alembic migrations (env.py, versions/)
├── tests/                    # Compliance checkers (not pytest unit tests)
│   ├── hardening_check.py      # Audits the 10 OS controls
│   └── db_hardening_check.py   # Audits the 7 PostgreSQL controls
├── setup_env.sh               # Phase 1: system user, sudoers, native dependencies
├── setup_web.sh                # Phase 2: virtualenv + Python dependencies
├── .env.example                # Environment variable template
└── web/requirements.txt        # Python dependencies for the web app
```

---

## ⚙️ Installation (Rocky Linux 9)

Installation happens in two phases via the scripts included at the project
root. **Running the app directly as root is discouraged**: the setup script
creates an isolated system user (`marandu`) with `sudo` permissions scoped
exclusively to the hardening scripts.

### Phase 1 — System environment (as root)

```bash
git clone https://github.com/usuario/MARANDU.git
cd MARANDU

sudo ./setup_env.sh
```

This script:
- Installs native dependencies (`python3`, `pgaudit_16`, `openssh-server`, `audit`)
- Creates the restricted system user `marandu`
- Configures `/etc/sudoers.d/marandu` with granular `NOPASSWD` rules,
  scoped exclusively to the scripts under `prevention/` and `tests/`
- Grants ownership of the project directory to the `marandu` user

### Phase 2 — Web environment (as the `marandu` user)

```bash
sudo -u marandu ./setup_web.sh
```

This script creates the virtual environment (`venv`) and installs the
dependencies listed in `web/requirements.txt` (falling back to `fastapi`,
`uvicorn`, and `pydantic` if that file doesn't exist yet).

### Additional OS requirements

If you'd rather install dependencies manually (e.g. in an environment where
`setup_env.sh` can't run), make sure you have:

```bash
sudo dnf install -y policycoreutils-python-utils audit audit-rules firewalld rsyslog openssl python3-devel gcc authselect pgaudit_16 acl
```

### Environment configuration

```bash
cp .env.example .env
```

| Variable                          | Description                                                                    |
|-------------------------------------|------------------------------------------------------------------------------------|
| `MARANDU_SECRET_KEY`               | Session cookie signing key. Generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `MARANDU_COOKIE_SECURE`            | `true` in production with HTTPS; `false` only for local development over HTTP    |
| `DATABASE_URL`                     | Async SQLAlchemy connection string, e.g. `postgresql+asyncpg://marandu_app:<password>@127.0.0.1:5432/marandu_dev` |
| `MARANDU_DB_HOST` / `MARANDU_DB_PORT` | PostgreSQL host and port used for DB audits (default `127.0.0.1:5432`)        |
| `MARANDU_DB_APP_PASSWORD`          | Password to assign to the `marandu_app` role when applying DB hardening from the dashboard |

> **Dashboard credentials are no longer stored in `.env`.** The
> `MARANDU_ADMIN_USER` / `MARANDU_ADMIN_PASSWORD_HASH` variables from
> earlier versions have been retired: users now live in the `usuarios_web`
> table in PostgreSQL. See **"Dashboard User Management"** below for how to
> create the first admin and any additional users.

### Running the web server

```bash
source venv/bin/activate
alembic -c db/alembic.ini upgrade head    # applies migrations, incl. usuarios_web
uvicorn web.app:app --host 0.0.0.0 --port 8000
```

The dashboard is then available at `http://<host>:8000/login`.

---

## 🔐 Dashboard User Management

Dashboard logins are validated against the `usuarios_web` table
(`db/models.py`) instead of the `.env` file. Passwords are hashed with
`bcrypt` before being stored, and are never handled in plain text outside
of the moment they're typed.

**By design, there is no way to create a user from the web interface.**
Exposing user creation as a web endpoint would put the most sensitive
operation in the system behind the same attack surface as everything else
(CSRF, session hijacking, an authorization bug, etc.). Instead, creating a
user requires **both**:

1. **Root access to the server** (something you have), and
2. **A master secret phrase** (something you know), verified against a
   bcrypt hash stored at `/etc/marandu/create_user.secret` (permissions
   `600`, owned by `root`).

Neither factor alone is enough to create a user.

### One-time setup: configure the master secret

```bash
sudo python3 web/scripts/setup_secreto_maestro.py
```

Prompts for a secret phrase (recommended: 20+ random characters or several
random words) and stores only its bcrypt hash. The plain phrase is never
persisted anywhere — save it in a password manager.

### Creating or updating a user

```bash
sudo python3 web/scripts/crear_usuario_cli.py
```

This script:
- Refuses to run unless invoked as root (`euid == 0`)
- Refuses to run if `/etc/marandu/create_user.secret` has loose permissions
- Prompts for the master secret (hidden input, 3 attempts with a backoff delay)
- Prompts for username, password (with confirmation), and role — **never**
  as command-line arguments, so nothing sensitive leaks into `ps aux` or
  shell history
- Inserts or updates the row in `usuarios_web`
- Logs every attempt (success or failure), including the invoking
  `$SUDO_USER`, to `/var/log/marandu/creacion_usuarios.log` for auditability

### Migrating from the legacy `.env`-based admin (one-time)

Projects upgraded from an earlier version that used
`MARANDU_ADMIN_USER` / `MARANDU_ADMIN_PASSWORD_HASH` can migrate that
account into the database once with:

```bash
python3 web/scripts/migrar_admin_env_a_db.py
```

After confirming the login works against the database, remove
`MARANDU_ADMIN_USER` and `MARANDU_ADMIN_PASSWORD_HASH` from `.env` — they
are no longer read by the application.

> `web/scripts/generar_hash.py` is kept as a lighter-weight, non-root helper
> for local/dev environments where the root + master-secret flow is
> unnecessary overhead. **It should not be used to manage production
> credentials** — use `crear_usuario_cli.py` for that.

---

## 🔒 Operating System Hardening (10 CIS controls)

Every control can be audited and applied from the web dashboard (one button
per control) or manually via its individual script.

| # | Control                                                | Applying script                            | Detail                                                                     |
|---|-----------------------------------------------------------|-----------------------------------------------|---------------------------------------------------------------------------------|
| 1 | SSH Hardening (root + port + key)                          | `prevention/ssh_hardening.py`                | Port `2222`, `PermitRootLogin no`, `PasswordAuthentication no`, SELinux port context + firewalld rule for the new port |
| 2 | Centralized rsyslog                                         | `prevention/rsyslog_centralization.py`       | Local retention in `/var/log/hips/syslog.log` + remote forwarding, weekly `logrotate` (4 rotations, compressed) |
| 3 | Login banner                                                 | `prevention/banner.py`                       | Configures `/etc/motd` and/or `/etc/issue`                                       |
| 4 | SELinux in Enforcing mode                                     | `prevention/selinux.py`                      | Applies `setenforce 1` live and persists `SELINUX=enforcing` in `/etc/selinux/config` |
| 5 | firewalld in a restrictive zone                                | `prevention/firewall.py`                     | Sets the default zone to `drop`, auto-detects the primary interface, and opens only `8000/tcp` (dashboard) and `2222/tcp` (SSH) |
| 6 | pam_faillock (lockout on failed attempts)                       | `prevention/pam_faillock.py`                 | Enables the `with-faillock` feature via `authselect`                             |
| 7 | Secure network sysctl parameters                                | `prevention/sysctl.py`                       | `ip_forward=0`, `accept_source_route=0`, `accept_redirects=0`, `secure_redirects=0`, `icmp_echo_ignore_broadcasts=1`, `rp_filter=1` (all/default) in `/etc/sysctl.d/99-sysctl.conf` |
| 8 | auditd — audit rules                                             | `prevention/auditd.py`                       | Watches `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` (`identity`/`actions`)  |
| 9 | Password policy (PAM pwquality)                                  | `prevention/password_hardening.py`           | `minlen=14`, `minclass=4`, `retry=3` in `/etc/security/pwquality.conf`, enabled via `authselect` |
| 10| `/tmp` mounted with `noexec`/`nosuid`/`nodev`                    | `prevention/secure_tmp_mount.py`             | Overrides `tmp.mount` under `/etc/systemd/system/` and remounts live             |

### Compliance verification (OS)

```bash
sudo python3 tests/hardening_check.py
```

Returns a dict with the status (`true`/`false`) of each of the 10 controls.
It's also queried automatically whenever `/dashboard` loads.

---

## 🔒 Database Hardening (PostgreSQL — 7 CIS controls)

### Applying hardening

```bash
sudo python3 prevention/db_auth.py -p <MARANDU_APP_PASSWORD> -u postgres -d <YOUR_DB>
```

This script:
- Enables `ssl=on`, `log_connections`/`log_disconnections`, and
  `password_encryption=scram-sha-256` in `postgresql.auto.conf`
- Replaces `md5`/`ident` with `scram-sha-256` in `pg_hba.conf`
- Creates a dedicated `marandu_app` role without `SUPERUSER`/`CREATEDB`/`CREATEROLE`
- Revokes `PUBLIC` privileges on the `public` schema
- Installs and enables the `pgaudit` extension (`pgaudit.log = 'all'`)

> ⚠️ **Note:** revoking `PUBLIC` privileges on the `public` schema also
> strips `marandu_app`'s own `CREATE`/`USAGE` grants unless they're
> explicitly re-added afterward. After running this control (from the CLI
> or the dashboard), re-grant what the app needs at runtime:
> ```sql
> GRANT USAGE ON SCHEMA public TO marandu_app;
> GRANT SELECT, INSERT, UPDATE, DELETE ON usuarios_web, alarmas, configuracion_modulos, eventos_raw, acciones_prevencion TO marandu_app;
> GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO marandu_app;
> ```
> Otherwise dashboard logins and alarm writes will fail with
> `InvalidSchemaNameError` / permission-denied errors until the grants are
> restored.

> From the dashboard, this control can be applied live via
> `POST /prevention/apply/{control_id}`, provided `MARANDU_DB_APP_PASSWORD`
> is set in the web app's `.env`.

### Compliance verification (DB)

```bash
sudo -u postgres python3 tests/db_hardening_check.py -H 127.0.0.1 -u postgres -d <YOUR_DB> -p <YOUR_PASSWORD>
```

| # | Control                                                    |
|---|----------------------------------------------------------------|
| 1 | TLS/SSL encryption enabled (`ssl=on`)                            |
| 2 | `marandu_app` role without superuser                              |
| 3 | Connection/disconnection audit logging                            |
| 4 | Restrictive host control (`pg_hba.conf` free of `md5`)             |
| 5 | Secure hashing algorithm (`scram-sha-256`)                         |
| 6 | Public privilege restriction on the `public` schema                |
| 7 | `pgaudit` extension installed and configured                        |

If all controls pass, the script prints `[+] COMPLIANCE OK` and exits with
status code `0`.

---

## 🖥️ Web Dashboard

- `GET /login` / `POST /login` — Login against the `usuarios_web` table
  (password verified with `bcrypt`, in constant time regardless of whether
  the username exists), protected by a CSRF token and IP-based rate
  limiting (5 failed attempts / 15 min lockout)
- `POST /logout` — Clears the session
- `GET /dashboard` — Live-audits the 10 OS controls; if DB credentials are
  submitted through the form, it also audits the 7 PostgreSQL controls (DB
  credentials are **not persisted**, they only travel with the request)
- `POST /prevention/apply/{control_id}` — Applies the given control
  (protected by a CSRF token and an authenticated admin session)

---

## 📋 Detection Modules

| #    | Module                          | File                              | Status                                                   |
|------|-------------------------------------|---------------------------------------|---------------------------------------------------------------|
| i    | File integrity                     | `detection/file_integrity.py`         | 🔲 Pending                                                       |
| ii   | Connected users                    | `detection/users_monitor.py`          | ✅ Implemented — parses `who`, alarms on untrusted origins (trusted IPs/CIDRs configurable via `MRND_TRUSTED_IPS`) |
| iii  | Sniffers & promiscuous mode        | `detection/sniffer_detect.py`         | 🔲 Pending                                                       |
| iv   | Log analysis                       | `detection/log_analyzer.py`           | 🔲 Pending                                                       |
| v    | Mail queue / mass spam             | `detection/mail_queue.py`             | 🔲 Pending                                                       |
| vi   | High-resource processes            | `detection/process_monitor.py`        | ✅ Implemented — configurable thresholds via `MRND_CPU_THRESHOLD` / `MRND_MEM_THRESHOLD`, with a process whitelist |
| vii  | Suspicious `/tmp` directory        | `detection/tmp_monitor.py`            | 🔲 Pending                                                       |
| viii | DDoS attacks                       | `detection/ddos_detect.py`            | 🔲 Pending                                                       |
| ix   | Suspicious cron files              | `detection/cron_monitor.py`           | 🔲 Pending                                                       |
| x    | Invalid access attempts            | `detection/access_monitor.py`         | 🔲 Pending                                                       |

The implemented modules (`ii` and `vi`) delegate alarm persistence to
`alerts/logger.py` (`log_event()`); until that central module is available,
both automatically fall back to a local writer that appends JSON-lines to
`/var/log/hips/` (or `./logs/` if root permissions aren't available).

---

## 📄 License

Academic project — Operating Systems 2 · 2026