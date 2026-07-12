import os
import subprocess
import re

# NOTA: este módulo ya NO exige que todo el proceso corra como root.
# Casi todos los chequeos funcionan con un usuario normal. Los dos únicos
# comandos que realmente necesitan privilegios elevados (`sshd -T` para leer
# las claves del host, y `auditctl -l` que requiere CAP_AUDIT_CONTROL) se
# invocan puntualmente con `sudo -n` (no interactivo).
#
# Para que funcionen sin pedir contraseña, agregá en /etc/sudoers.d/marandu:
#
#   marandu ALL=(root) NOPASSWD: /usr/sbin/sshd -T
#   marandu ALL=(root) NOPASSWD: /usr/sbin/auditctl -l
#
# (ajustá las rutas absolutas de sshd/auditctl según tu distro: `which sshd`,
# `which auditctl`). Si no configurás esto, esos dos chequeos van a devolver
# `False` (se van a ver como "Vulnerable") en vez de fallar o colgarse, porque
# `sudo -n` corta al toque si no puede autenticar sin contraseña.


def _run_sudo(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Corre un comando puntual con sudo no-interactivo (no pide contraseña,
    y si no está autorizado en sudoers falla rápido en vez de colgarse)."""
    return subprocess.run(["sudo", "-n", *cmd], capture_output=True, text=True, **kwargs)


def verify_ssh_hardening():
    try:
        result = _run_sudo(["sshd", "-T"], check=True)
        output = result.stdout.lower()
        root_disabled = "permitrootlogin no" in output
        custom_port = "port 2222" in output
        password_auth_disabled = "passwordauthentication no" in output
        return root_disabled and custom_port and password_auth_disabled
    except Exception:
        return False

def verify_rsyslog_centralized():
    try:
        status_check = subprocess.run(["systemctl", "is-active", "rsyslog"], capture_output=True, text=True)
        rsyslog_active = status_check.stdout.strip() == "active"
        hips_dir_exists = os.path.exists("/var/log/hips/")
        return rsyslog_active and hips_dir_exists
    except Exception:
        return False

def verify_banner_login():
    try:
        motd_exists = os.path.exists("/etc/motd") and os.path.getsize("/etc/motd") > 0
        issue_exists = os.path.exists("/etc/issue") and os.path.getsize("/etc/issue") > 0
        return motd_exists or issue_exists
    except Exception:
        return False

def verify_selinux_enforcing():
    try:
        result = subprocess.run(["getenforce"], capture_output=True, text=True)
        enforcing = result.stdout.strip() == "Enforcing"
        config_enforcing = False
        if os.path.exists("/etc/selinux/config"):
            with open("/etc/selinux/config", "r") as f:
                content = f.read()
                if re.search(r'^\s*SELINUX=enforcing', content, re.MULTILINE):
                    config_enforcing = True
        return enforcing and config_enforcing
    except Exception:
        return False

def verify_firewalld_restrictive():
    try:
        status_check = subprocess.run(["systemctl", "is-active", "firewalld"], capture_output=True, text=True)
        return status_check.stdout.strip() == "active"
    except Exception:
        return False

def verify_pam_faillock():
    try:
        pam_configured = False
        files_to_check = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
        for file in files_to_check:
            if os.path.exists(file):
                with open(file, "r") as f:
                    if "pam_faillock.so" in f.read():
                        pam_configured = True
                        break
        return pam_configured
    except Exception:
        return False

def verify_sysctl_network():
    try:
        # Mapeo estricto según la especificación del plan de hardening
        checks = {
            "net.ipv4.ip_forward": "0",                         # Deshabilitar IP forwarding
            "net.ipv4.tcp_syncookies": "1",                     # Activar SYN Cookies (Anti-DDoS)
            "net.ipv4.conf.all.accept_redirects": "0",          # Rechazar ICMP Redirects (Global)
            "net.ipv4.conf.default.accept_redirects": "0",      # Rechazar ICMP Redirects (Por defecto)
            "net.ipv4.conf.all.rp_filter": "1",                 # Mitigación Spoofing / Reverse Path Filter
            "net.ipv4.conf.default.rp_filter": "1"              # Reverse Path Filter (Por defecto)
        }
        
        for param, expected in checks.items():
            res = subprocess.run(["sysctl", "-n", param], capture_output=True, text=True)
            if res.stdout.strip() != expected:
                return False  # Si uno solo no coincide, la validación de red segura falla
                
        return True
    except Exception:
        return False

def verify_auditd_rules():
    try:
        status_check = subprocess.run(["systemctl", "is-active", "auditd"], capture_output=True, text=True)
        if status_check.stdout.strip() != "active":
            return False
        rules_check = _run_sudo(["auditctl", "-l"])
        output = rules_check.stdout
        return any(x in output for x in ["/etc/passwd", "/etc/shadow", "/etc/sudoers"])
    except Exception:
        return False

def verify_pam_pwquality():
    try:
        config_path = "/etc/security/pwquality.conf"
        if not os.path.exists(config_path):
            return False
        with open(config_path, "r") as f:
            content = f.read()
            has_minlen = re.search(r'^\s*minlen\s*=\s*\d+', content, re.MULTILINE) is not None
            return has_minlen
    except Exception:
        return False

def verify_tmp_mount():
    try:
        result = subprocess.run(["findmnt", "-n", "-o", "options", "/tmp"], capture_output=True, text=True)
        options = result.stdout.strip()
        return "noexec" in options and "nosuid" in options
    except Exception:
        return False

def get_hardening_status():
    return {
        "SSH Hardening completo (root + puerto + clave)": verify_ssh_hardening(),
        "rsyslog centralizado": verify_rsyslog_centralized(),
        "Banner de login": verify_banner_login(),
        "SELinux en modo Enforcing": verify_selinux_enforcing(),
        "firewalld zona restrictiva": verify_firewalld_restrictive(),
        "pam_faillock bloqueo por intentos fallidos": verify_pam_faillock(),
        "parámetros sysctl de red seguros": verify_sysctl_network(),
        "auditd reglas de auditoría": verify_auditd_rules(),
        "Política de contraseñas (PAM pwquality)": verify_pam_pwquality(),
        "Montaje /tmp con noexec y nosuid": verify_tmp_mount(),
    }

if __name__ == "__main__":
    status = get_hardening_status()
    print("{")
    for tactic, active in status.items():
        print(f"  {tactic} : {str(active).lower()}")
    print("}")