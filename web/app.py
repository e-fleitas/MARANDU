import os
import subprocess
from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# Si es necesario, podés modularizar e importar las funciones de check
from tests.hardening_check import get_hardening_status

app = FastAPI(title="M.A.R.A.N.D.U. Dashboard")

# Configuración de templates Jinja2 (acorde a tu stack)
templates = Jinja2Templates(directory="web/templates")

# Mapeo de controles hacia sus respectivos scripts de aplicación
STRATEGY_SCRIPTS = {
    "ssh": "prevention/ssh_hardening.py",
    "rsyslog": "prevention/rsyslog_centralization.py",
    "banner": "prevention/banner.py",
    "selinux": "prevention/selinux.py",
    "firewall": "prevention/firewall.py",
    "pam_faillock": "prevention/pam_faillock.py",
    "sysctl": "prevention/sysctl.py",
    "auditd": "prevention/auditd.py",
    "pwquality": "prevention/password_hardening.py",
    "tmp": "prevention/secure_tmp_mount.py"
}

# Diccionario interno para mapear la salida de get_hardening_status a IDs simplificados
MAPPING_KEYS = {
    "SSH Hardening completo (root + puerto + clave)": "ssh",
    "rsyslog centralizado": "rsyslog",
    "Banner de login": "banner",
    "SELinux en modo Enforcing": "selinux",
    "firewalld zona restrictiva": "firewall",
    "pam_faillock bloqueo por intentos fallidos": "pam_faillock",
    "parámetros sysctl de red seguros": "sysctl",
    "auditd reglas de auditoría": "auditd",
    "Política de contraseñas (PAM pwquality)": "pwquality",
    "Montaje /tmp con noexec y nosuid": "tmp"
}

@app.get("/dashboard", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    # 1. Obtener estados de hardening actuales usando tu checker existente
    raw_status = get_hardening_status()
    print(raw_status)
    
    # Estandarizamos la estructura para iterar de manera simple en el HTML
    controls = []
    for description, active in raw_status.items():
        slug = MAPPING_KEYS.get(description, "unknown")
        controls.append({
            "id": slug,
            "description": description,
            "status": "COMPLIANT" if active else "VULNERABLE",
            "active": active
        })
        
    return templates.TemplateResponse(
    request=request, 
    name="dashboard.html", 
    context={"controls": controls}
)

@app.post("/prevention/apply/{control_id}")
async def apply_hardening(control_id: str):
    if control_id not in STRATEGY_SCRIPTS:
        raise HTTPException(status_code=400, detail="Estrategia de hardening inválida.")
        
    script_path = STRATEGY_SCRIPTS[control_id]
    
    # Ejecutamos el script correspondiente como root vía subprocess (acorde a la justificación de tu stack[cite: 1, 2])
    try:
        result = subprocess.run(
            ["sudo", "python3", script_path],
            capture_output=True,
            text=True,
            check=True
        )
        return {"status": "success", "message": f"Control {control_id} aplicado.", "output": result.stdout}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error al aplicar hardening: {e.stderr}")