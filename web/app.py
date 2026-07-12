import os
import subprocess
from dotenv import load_dotenv
from pathlib import Path
import bcrypt  # Requerido para verificar el hash del .env
from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# ==============================================================================
# 1. CONFIGURACIÓN DE RUTAS Y ENTORNO
# ==============================================================================
# BASE_DIR se calcula de primero para evitar NameError en cascada
BASE_DIR = Path(__file__).resolve().parent.parent

# ⚡ ¡AGREGÁ ESTA LÍNEA ACÁ! Para que busque y cargue el archivo de la raíz
load_dotenv(dotenv_path=BASE_DIR / ".env")

# Rutas físicas hacia los scripts de remediación
DB_AUTH_SCRIPT = str(BASE_DIR / "prevention" / "db_auth.py")

STRATEGY_SCRIPTS = {
    "os_shm": str(BASE_DIR / "prevention" / "os_shm.py"),
    "os_aslr": str(BASE_DIR / "prevention" / "os_aslr.py"),
}

# ==============================================================================
# 2. INICIALIZACIÓN DE LA APLICACIÓN Y MIDDLEWARES
# ==============================================================================
app = FastAPI(title="MARANDU HIPS")

# Extracción de directivas del archivo .env
SECRET_KEY = os.environ.get("MARANDU_SECRET_KEY", "clave_defecto_marandu_32_bytes_minimo")
COOKIE_SECURE = os.environ.get("MARANDU_COOKIE_SECURE", "false").lower() == "true"

# Montaje estructural del SessionMiddleware para evitar el AssertionError
# Modificación en web/app.py

app.add_middleware(
    SessionMiddleware, 
    secret_key=SECRET_KEY,
    session_cookie="marandu_session",
    https_only=COOKIE_SECURE,  # <-- CAMBIAR 'secure' POR 'https_only'
    same_site="lax"
)

templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))

# ==============================================================================
# 3. IMPORTACIONES Y MAPEOS DEL PROYECTO
# ==============================================================================
from tests.db_hardening_check import get_db_hardening_status_dict

MAPPING_KEYS = {
    "Protección de Memoria Compartida (/dev/shm)": "os_shm",
    "Aleatorización del Espacio de Direcciones (ASLR)": "os_aslr",
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
    """Verifica si el usuario en sesión coincide con el administrador del .env."""
    user = request.session.get("user")
    admin_user = os.environ.get("MARANDU_ADMIN_USER", "admin")

    if not user or user != admin_user:
        raise HTTPException(status_code=401, detail="Sesión inválida o no autorizada.")
    return user

def get_csrf_token(request: Request) -> str:
    """Retorna un token de validación CSRF estático para la interfaz."""
    return "token_secreto_marandu_hips"

def verify_csrf(request: Request, token: str) -> bool:
    """Valida la integridad del token CSRF."""
    return token == "token_secreto_marandu_hips"

def get_hardening_status():
    """Simulación/Auditoría local de controles de Sistema Operativo."""
    return {
        "Protección de Memoria Compartida (/dev/shm)": True,
        "Aleatorización del Espacio de Direcciones (ASLR)": False
    }

# ==============================================================================
# 5. ENDPOINTS DE AUTENTICACIÓN CENTRALIZADA
# ==============================================================================
@app.get("/login", response_class=HTMLResponse)
async def get_login_page(request: Request):
    """Muestra el formulario HTML de inicio de sesión."""
    return templates.TemplateResponse(request=request, name="login.html")
@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Valida credenciales usando checkpw contra el hash bcrypt del .env."""
    admin_user = os.environ.get("MARANDU_ADMIN_USER", "admin")
    admin_hash = os.environ.get("MARANDU_ADMIN_PASSWORD_HASH", "")

    if username != admin_user:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos.")

    if not admin_hash:
        raise HTTPException(status_code=500, detail="Error de entorno: Falta la firma HASH.")

    # Bcrypt requiere que los inputs sean casteados a bytes obligatoriamente
    password_bytes = password.encode("utf-8")
    hash_bytes = admin_hash.encode("utf-8")

    if bcrypt.checkpw(password_bytes, hash_bytes):
        request.session["user"] = username
        return RedirectResponse(url="/dashboard", status_code=303)
    else:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos.")

@app.post("/logout")
async def logout(request: Request):
    """Destruye los datos temporales del cliente en la cookie."""
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

# ==============================================================================
# 6. ENDPOINTS DEL DASHBOARD Y REMEDIACIONES EN CALIENTE
# ==============================================================================
@app.get("/dashboard", response_class=HTMLResponse)
async def read_dashboard(
    request: Request, 
    db_user: str = None,      # Cambiado a None por defecto para detectar si el usuario interactuó
    db_name: str = None,      # Cambiado a None por defecto
    db_password: str = None,  # Captura la contraseña desde el formulario gráfico
    user: str = Depends(login_required)
):
    # --- 1. Evaluación Automática de Sistema Operativo ---
    raw_status = get_hardening_status()
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
    
    # Flag para que tu HTML sepa si debe mostrar el formulario de login o los resultados
    necesita_credenciales = True 

    # Evaluamos si el administrador ya envió el formulario gráfico con datos
    if db_user and db_name and db_password:
        necesita_credenciales = False
        db_host = os.environ.get("MARANDU_DB_HOST", "127.0.0.1")
        db_port = os.environ.get("MARANDU_DB_PORT", "5432")
        
        try:
            # Ejecuta la auditoría únicamente si se ingresaron las credenciales desde la web
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
            # Si las credenciales fallan o no conecta, volvemos a pedir datos mostrando el error
            necesita_credenciales = True
            error_db = f"Fallo de conexión a PostgreSQL: {str(e)}"

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "controls": controls,
            "db_controls": db_controls,
            "db_user": db_user or "postgres",   # Para rellenar el input del HTML por comodidad
            "db_name": db_name or "postgres",   # Para rellenar el input del HTML por comodidad
            "necesita_credenciales": necesita_credenciales, # <-- Variable clave para tu template Jinja
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
    
    # Si la petición es DB, capturamos el JSON dinámico enviado por el cliente
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
        
        # Invocación recursiva delegando los flags dinámicos de administración -u y -d
        cmd = ["sudo", "python3", DB_AUTH_SCRIPT, "-p", app_db_password, "-u", req_db_user, "-d", req_db_name]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=120,
            )
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