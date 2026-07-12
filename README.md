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
- Provide a login-protected web interface (bcrypt + session cookies) to
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
| OS interaction        | `subprocess`, `psutil`, `os`               | Direct access to processes, network, PAM, SELinux, and firewalld  |
| Web authentication    | `bcrypt` + `SessionMiddleware` (Starlette) | Secure admin password hashing + signed session cookies             |
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
│   ├── auth.py
│   ├── templates/             # dashboard.html, login.html
│   └── scripts/
│       └── generar_hash.py     # Generates the admin's bcrypt hash
├── db/                       # SQLAlchemy models and async session
│   ├── models.py               # UsuarioWeb, Alarma, AccionPrevencion, ConfiguracionModulo
│   └── session.py
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
| `MARANDU_ADMIN_USER`               | Dashboard admin username (default: `admin`)                                     |
| `MARANDU_ADMIN_PASSWORD_HASH`      | bcrypt hash of the admin password. Generate with `python web/scripts/generar_hash.py` |
| `MARANDU_COOKIE_SECURE`            | `true` in production with HTTPS; `false` only for local development over HTTP    |
| `MARANDU_DB_HOST` / `MARANDU_DB_PORT` | PostgreSQL host and port used for DB audits (default `127.0.0.1:5432`)        |
| `MARANDU_DB_APP_PASSWORD`          | Password to assign to the `marandu_app` role when applying DB hardening from the dashboard |

> Never generate the admin password hash by hand: always use
> `python web/scripts/generar_hash.py`, which validates the minimum length
> and safely truncates to the 72 bytes bcrypt supports.

### Running the web server

```bash
source venv/bin/activate
uvicorn web.app:app --host 0.0.0.0 --port 8000
```

The dashboard is then available at `http://<host>:8000/login`.

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

- `GET /login` / `POST /login` — Login against `MARANDU_ADMIN_USER` +
  `MARANDU_ADMIN_PASSWORD_HASH` (verified with `bcrypt`)
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