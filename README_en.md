# M.A.R.A.N.D.U.
### Malicious Attack Response, Analysis, and Network Detection Unit

A Host-based Intrusion Prevention System (HIPS) developed as Practical
Assignment #2 for the **Operating Systems 2** course.

The system runs on **Rocky Linux** (latest stable version) and integrates
detection modules, automated prevention, and a real-time web alert dashboard.

---

## 🎯 System Objectives

- Detect and automatically respond to host-level threats (file integrity,
  sniffers, brute force, malicious processes, DDoS attacks, etc.)
- Log all alarms to `/var/log/hips/` in a standardized format
- Notify the administrator via email for every security event
- Provide a login-protected web interface for configuration and monitoring
- Apply at least 10 hardening controls on Rocky Linux and 7 on PostgreSQL
  (CIS Benchmark)

---

## 👥 Team Members

| Name                 | ID       | Primary Role                         |
|----------------------|----------|--------------------------------------|
| [Member 1]           | XXXXXX   | Detection modules + Database         |
| [Member 2]           | XXXXXX   | Web interface + Prevention module    |

---

## 🛠️ Technology Stack

| Component          | Technology                              | Justification                                                  |
|--------------------|-----------------------------------------|----------------------------------------------------------------|
| Main language      | Python 3.x                              | Full ecosystem for syscalls, log parsing, and OS scripting     |
| Web framework      | FastAPI                                 | Native async, automatic validation, built-in Swagger docs      |
| Database           | PostgreSQL                              | Mandatory course requirement                                   |
| DB connector       | psycopg2 / SQLAlchemy                   | Standard ORM with async support                                |
| OS interaction     | subprocess + psutil + os                | Direct access to processes, network, and filesystem            |
| Email alerts       | smtplib (stdlib)                        | No external dependencies for notifications                     |
| Testing            | pytest                                  | Standard Python automated testing framework                    |
| OS Hardening       | SELinux, firewalld, auditd, SSH, etc.   | CIS Benchmark for Rocky Linux                                  |
| DB Hardening       | CIS PostgreSQL Benchmark (7 controls)  | Data layer security                                            |

---

## 📁 Project Structure
MARANDU/
├── detection/          # Detection modules i–x
├── prevention/         # Automated prevention actions
├── alerts/             # Central logger and email notifications
├── web/                # FastAPI app + templates
├── db/                 # PostgreSQL models and migrations
├── config/             # Encrypted configuration (never commit real .env)
├── tests/              # Automated tests with pytest
├── docs/               # User and installation manuals
├── .env.example        # Environment variable template
└── requirements.txt    # Python dependencies

---
## Operating System Requirements
Before running the HIPS, ensure that the native dependencies are installed on Rocky Linux:

```bash
sudo dnf install -y policycoreutils-python-utils audit audit-rules firewalld rsyslog openssl python3-devel gcc authselect pgaudit_16 acl
```
---

## ⚙️ Quick Start

```bash
git clone https://github.com/usuario/MARANDU.git
cd MARANDU

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with real values

uvicorn web.app:app --host 0.0.0.0 --port 8000
```

---

## 🔒 Database Hardening (PostgreSQL)
El sistema incluye una suite de hardening para PostgreSQL basada en el estándar CIS.

### Applying Hardening
To automatically apply the 7 security controls to the database (including TLS, roles, privileges, and auditing), run:

```bash
sudo python3 prevention/db_auth.py -p <YOUR_PASSWORD> -d <your_DB> -u postgres
```

---
## Compliance Verification (Checker)
To audit that the controls remain active and properly configured, use the verification tool:

```bash
sudo -u postgres python3 tests/db_hardening_check.py -d marandu_test -u postgres -H 127.0.0.1 -p <YOUR_PASSWORD>
```
If all controls pass, the script will display [+] COMPLIANCE OK.
---

---

## 📋 Detection Modules

| #    | Module                         | File                              |
|------|--------------------------------|-----------------------------------|
| i    | File integrity                 | `detection/file_integrity.py`     |
| ii   | Connected users                | `detection/users_monitor.py`      |
| iii  | Sniffers & promiscuous mode    | `detection/sniffer_detect.py`     |
| iv   | Log analysis                   | `detection/log_analyzer.py`       |
| v    | Mail queue / mass spam         | `detection/mail_queue.py`         |
| vi   | High-resource processes        | `detection/process_monitor.py`    |
| vii  | Suspicious /tmp directory      | `detection/tmp_monitor.py`        |
| viii | DDoS attacks                   | `detection/ddos_detect.py`        |
| ix   | Suspicious cron files          | `detection/cron_monitor.py`       |
| x    | Invalid access attempts        | `detection/access_monitor.py`     |

---

## 📄 License

Academic project — Operating Systems 2 · 2026
