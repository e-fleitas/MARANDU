import os
import subprocess
from dotenv import load_dotenv
from pathlib import Path
import bcrypt
from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# ==============================================================================
# 1. CONFIGURACIÓN DE RUTAS Y ENTORNO
# ==============================================================================
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

# Rutas físicas hacia los scripts de remediación
DB_AUTH_SCRIPT = str(BASE_DIR / "prevention" / "db_auth.py")

# ⚡ MAPEO DE TODOS LOS SCRIPTS DE HARDENING DE OS (Carpeta prevention/)
STRATEGY_SCRIPTS = {
    "ssh_hardening": str(BASE_DIR / "prevention" / "ssh_hardening.py"),
    "rsyslog_centralized": str(BASE_DIR / "prevention" / "rsyslog_centralization.py"),
    "banner_login": str(BASE_DIR / "prevention" / "banner.py"),
    "selinux_enforcing": str(BASE_DIR / "prevention" / "selinux.py"),
    "firewall_restrictive": str(BASE_DIR / "prevention" / "firewall.py"),
    "pam_faillock": str(BASE_DIR / "prevention" / "pam_faillock.py"),
    "sysctl_network": str(BASE_DIR / "prevention" / "sysctl.py"),
    "auditd_rules": str(BASE_DIR / "prevention" / "auditd.py"),
    "pam_pwquality": str(BASE_DIR / "prevention" / "password_hardening.py"),
    "tmp_mount": str(BASE_DIR / "prevention" / "secure_tmp_mount.py"),
}

# ==============================================================================
# 2. INICIALIZACIÓN DE LA APLICACIÓN Y MIDDLEWARES
# ==============================================================================
app = FastAPI(title="MARANDU HIPS")

SECRET_KEY = os.environ.get("MARANDU_SECRET_KEY", "clave_defecto_marandu_32_bytes_minimo")
COOKIE_SECURE = os.environ.get("MARANDU_COOKIE_SECURE", "false").lower() == "true"

app.add_middleware(
    SessionMiddleware, 
    secret_key=SECRET_KEY,
    session_cookie="marandu_session",
    https_only=COOKIE_SECURE,
    same_site="lax"
)

templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))

# ==============================================================================
# 3. IMPORTACIONES Y MAPEOS DEL PROYECTO
# ==============================================================================
from tests.db_hardening_check import get_db_hardening_status_dict
# ⚡ IMPORTAMOS TU AUDITORÍA REAL DE SISTEMA OPERATIVO
from tests.hardening_check import get_hardening_status as get_os_hardening_status

# ⚡ MAPEO EXACTO DE LAS DESCRIPCIONES DE hardening_check.py HACIA LOS IDS
MAPPING_KEYS = {
    "SSH Hardening completo (root + puerto + clave)": "ssh_hardening",
    "rsyslog centralizado": "rsyslog_centralized",
    "Banner de login": "banner_login",
    "SELinux en modo Enforcing": "selinux_enforcing",
    "firewalld zona restrictiva": "firewall_restrictive",
    "pam_faillock bloqueo por intentos fallidos": "pam_faillock",
    "parámetros sysctl de red seguros": "sysctl_network",
    "auditd reglas de auditoría": "auditd_rules",
    "Política de contraseñas (PAM pwquality)": "pam_pwquality",
    "Montaje /tmp con noexec y nosuid": "tmp_mount",
}

DB_MAPPING_KEYS = {
    "Cifrado TLS/SSL Activo (ssl=on)": "db_ssl",
    "Rol 'marandu_app' sin Superusuario": "db_role",
    "Registro de Auditoría (connections/disconnections)": "db_logging",
    "Control Restrictivo de Hosts (pg_hba.conf sin md5)": "db_hba",
    "Algoritmo de Hashing Seguro (scram-sha-256)": "db_auth",
    "Restricción de Privilegios Públicos en Schema Public": "db_public",
    "Extensión pgaudit Instalada y Configurada": "db_pgaudit"
}

# ==============================================================================
# 4. DEPENDENCIAS DE CONTROL DE ACCESO Y SEGURIDAD
# ==============================================================================
def login_required(request: Request):
    user = request.session.get("user")
    admin_user = os.environ.get("MARANDU_ADMIN_USER", "admin")
    if not user or user != admin_user:
        raise HTTPException(status_code=401, detail="Sesión inválida o no autorizada.")
    return user

def get_csrf_token(request: Request) -> str:
    return "token_secreto_marandu_hips"

def verify_csrf(request: Request, token: str) -> bool:
    return token == "token_secreto_marandu_hips"

# ==============================================================================
# 5. ENDPOINTS DE AUTENTICACIÓN CENTRALIZADA
# ==============================================================================
@app.get("/login", response_class=HTMLResponse)
async def get_login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    admin_user = os.environ.get("MARANDU_ADMIN_USER", "admin")
    admin_hash = os.environ.get("MARANDU_ADMIN_PASSWORD_HASH", "")

    if username != admin_user or not admin_hash:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos.")

    if bcrypt.checkpw(password.encode("utf-8"), admin_hash.encode("utf-8")):
        request.session["user"] = username
        return RedirectResponse(url="/dashboard", status_code=303)
    else:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos.")

@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

# ==============================================================================
# 6. ENDPOINTS DEL DASHBOARD Y REMEDIACIONES EN CALIENTE
# ==============================================================================
@app.get("/dashboard", response_class=HTMLResponse)
async def read_dashboard(
    request: Request, 
    db_user: str = None,
    db_name: str = None,
    db_password: str = None,
    user: str = Depends(login_required)
):
    # --- 1. Evaluación Real de Sistema Operativo ---
    raw_status = get_os_hardening_status() # ⚡ LLAMA A LOS 10 CONTROLES REALES
    controls = []
    for description, active in raw_status.items():
        slug = MAPPING_KEYS.get(description, "unknown")
        controls.append({
            "id": slug,
            "description": description,
            "status": "COMPLIANT" if active else "VULNERABLE",
            "active": active
        })

    # --- 2. Lógica de Interfaz Dinámica para PostgreSQL ---
    db_controls = []
    error_db = None
    necesita_credenciales = True 

    # Evalúa si el usuario envió el formulario con la clave de BD
    if db_user and db_name and db_password:
        necesita_credenciales = False
        db_host = os.environ.get("MARANDU_DB_HOST", "127.0.0.1")
        db_port = os.environ.get("MARANDU_DB_PORT", "5432")
        
        try:
            raw_db_status = get_db_hardening_status_dict(
                host=db_host, port=db_port, user=db_user, dbname=db_name, password=db_password
            )
            for description, active in raw_db_status.items():
                slug = DB_MAPPING_KEYS.get(description, "unknown")
                db_controls.append({
                    "id": slug,
                    "description": description,
                    "status": "COMPLIANT" if active else "VULNERABLE",
                    "active": active
                })
        except Exception as e:
            necesita_credenciales = True
            error_db = f"Fallo de conexión a PostgreSQL: {str(e)}"

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "controls": controls,
            "db_controls": db_controls,
            "db_user": db_user or "postgres",
            "db_name": db_name or "postgres",
            "necesita_credenciales": necesita_credenciales,
            "error_db": error_db,
            "csrf_token": get_csrf_token(request),
            "user": user,
        }
    )

@app.post("/prevention/apply/{control_id}")
async def apply_hardening(control_id: str, request: Request, user: str = Depends(login_required)):
    csrf_header = request.headers.get("X-CSRF-Token", "")
    if not verify_csrf(request, csrf_header):
        raise HTTPException(status_code=403, detail="Token CSRF inválido o ausente.")

    req_db_user = "postgres"
    req_db_name = "postgres"
    
    if request.headers.get("content-type") == "application/json":
        try:
            body = await request.json()
            req_db_user = body.get("db_user", "postgres")
            req_db_name = body.get("db_name", "postgres")
        except Exception:
            pass

    # A. INTERCEPCIÓN PARA MEDIDAS POSTGRESQL
    if control_id in DB_MAPPING_KEYS.values():
        app_db_password = os.environ.get("MARANDU_DB_APP_PASSWORD")
        if not app_db_password:
            raise HTTPException(
                status_code=500, 
                detail="Falta configurar MARANDU_DB_APP_PASSWORD en el archivo .env web."
            )
        
        cmd = ["sudo", "python3", DB_AUTH_SCRIPT, "-p", app_db_password, "-u", req_db_user, "-d", req_db_name]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
            return {
                "status": "success", 
                "message": f"Hardening general aplicado exitosamente en DB '{req_db_name}' con usuario admin '{req_db_user}'.", 
                "output": result.stdout
            }
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Error al aplicar hardening en DB: {e.stderr}")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="El script de hardening de DB superó el tiempo límite.")

    # B. FLUJO PARA MEDIDAS DEL SISTEMA OPERATIVO
    if control_id not in STRATEGY_SCRIPTS:
        raise HTTPException(status_code=400, detail="Estrategia de hardening inválida.")

    script_path = STRATEGY_SCRIPTS[control_id]
    try:
        result = subprocess.run(
            ["sudo", "python3", script_path],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        return {"status": "success", "message": f"Control {control_id} aplicado.", "output": result.stdout}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error al aplicar hardening: {e.stderr}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="El script para '{control_id}' superó el tiempo límite.")