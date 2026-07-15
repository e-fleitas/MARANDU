"""
db/seed_config.py

Deja la base de datos de M.A.R.A.N.D.U. lista para operar:

  1. Crea las tablas del modelo (Base.metadata.create_all) si no existen.
  2. Carga en `configuracion_modulos` las filas de cada grupo de estrategia
     de mitigación (minimo / moderado / agresivo, ver prevention/strategia.py),
     dejando activo el nivel por defecto más razonable para cada grupo,
     respetando siempre su piso de seguridad (PISO_NIVEL).
  3. Carga los parámetros de notificación SMTP (smtp_host, smtp_port,
     smtp_user, smtp_pass, admin_email) leídos de variables de entorno, si
     están presentes. Nunca hardcodea secretos: si una variable no está
     seteada, se omite y se avisa por consola para correr el seed de nuevo
     más adelante.

Idempotente: correrlo varias veces no duplica filas (hay un
UniqueConstraint en (modulo, parametro)) ni pisa un nivel que un admin ya
haya cambiado a mano desde el panel.

Uso (con el venv activado, desde la raíz del proyecto):
    python -m db.seed_config
"""

import asyncio
import os

from sqlalchemy import select

from db.models import Base, ConfiguracionModulo
from db.session import engine, async_session
from prevention.strategia import NIVELES, PISO_NIVEL

# Nivel activo por defecto para un grupo recién creado. "moderado" es la
# postura por defecto más razonable: a diferencia de "minimo" nunca deja
# una alarma sin ninguna respuesta automática, pero tampoco arranca en el
# modo más disruptivo ("agresivo") sin que un admin lo decida
# explícitamente desde el panel.
DEFAULT_NIVEL = "moderado"

NOTIF_GRUPO = "notificaciones"
NOTIF_PARAMS = ("smtp_host", "smtp_port", "smtp_user", "smtp_pass", "admin_email")

# Grupos de mitigación que solucionan las discordancias con el manual.
# Aseguramos sus pisos de seguridad mínimos según su criticidad.
PISOS_ADICIONALES = {
    "integridad_sistema": "moderado",  # Para MODIFICACION_PASSWD y MODIFICACION_SHADOW
    "cron_sospechoso": "minimo",       # Para CRON_SOSPECHOSO
    "credential_stuffing": "moderado"  # Para CREDENTIAL_STUFFING
}


async def _crear_tablas() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[+] Tablas verificadas/creadas.")


async def _sembrar_grupo_estrategia(session, grupo: str, piso: str) -> int:
    """Inserta las filas faltantes de un grupo. Si el grupo no tiene
    todavía ningún nivel activo, activa DEFAULT_NIVEL (o el piso del
    grupo si DEFAULT_NIVEL queda por debajo de él). Si el grupo ya tiene
    un nivel activo (configurado antes, a mano o en una corrida previa),
    no lo toca."""
    stmt = select(ConfiguracionModulo).where(ConfiguracionModulo.modulo == grupo)
    filas_existentes = {f.parametro: f for f in (await session.execute(stmt)).scalars().all()}
    ya_tiene_activo = any(f.activo for f in filas_existentes.values())

    nivel_default = DEFAULT_NIVEL
    if NIVELES.index(nivel_default) < NIVELES.index(piso):
        nivel_default = piso  # nunca sembrar por debajo del piso del grupo

    creadas = 0
    for nivel in NIVELES:
        if nivel in filas_existentes:
            # Ya existe la fila; si por algún motivo el grupo quedó sin
            # ningún nivel activo, activamos la que corresponde al
            # default en vez de dejar el grupo completamente apagado.
            if not ya_tiene_activo and nivel == nivel_default:
                filas_existentes[nivel].activo = True
                ya_tiene_activo = True
            continue

        activar = (not ya_tiene_activo) and (nivel == nivel_default)
        if activar:
            ya_tiene_activo = True
        session.add(ConfiguracionModulo(modulo=grupo, parametro=nivel, valor=nivel, activo=activar))
        creadas += 1

    return creadas


async def _sembrar_notificaciones(session) -> list[str]:
    stmt = select(ConfiguracionModulo).where(ConfiguracionModulo.modulo == NOTIF_GRUPO)
    existentes = {f.parametro for f in (await session.execute(stmt)).scalars().all()}

    faltantes = []
    for clave in NOTIF_PARAMS:
        if clave in existentes:
            continue
        valor = os.getenv(clave.upper())
        if valor:
            session.add(ConfiguracionModulo(modulo=NOTIF_GRUPO, parametro=clave, valor=valor, activo=True))
        else:
            faltantes.append(clave)
    return faltantes


async def main() -> None:
    await _crear_tablas()

    # Combinamos dinámicamente los pisos de estrategia base y los nuevos grupos
    # para evitar duplicaciones y mantener la compatibilidad con strategia.py
    todos_los_pisos = {**PISO_NIVEL, **PISOS_ADICIONALES}

    async with async_session() as session:
        total_creadas = 0
        for grupo, piso in todos_los_pisos.items():
            total_creadas += await _sembrar_grupo_estrategia(session, grupo, piso)

        faltantes = await _sembrar_notificaciones(session)
        await session.commit()

    print(
        f"[+] {total_creadas} filas de estrategia insertadas/completadas "
        f"(nivel por defecto: '{DEFAULT_NIVEL}', respetando el piso de cada grupo)."
    )
    if faltantes:
        print(f"[!] No se cargó configuración SMTP para: {', '.join(faltantes)}.")
        print(
            "    Definí las variables de entorno correspondientes "
            "(SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ADMIN_EMAIL) "
            "y volvé a correr 'python -m db.seed_config'."
        )
    else:
        print("[+] Configuración de notificaciones SMTP cargada.")


if __name__ == "__main__":
    asyncio.run(main())