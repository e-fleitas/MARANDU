"""
prevention/estrategias.py

Manejo de "estrategias" de mitigación con exclusión mutua, con TRES niveles:

    minimo   -> solo notificar al admin, sin acción automática sobre el sistema.
    moderado -> acción reversible / de bajo impacto (rate-limit, bloqueo temporal,
                cuarentena, prioridad reducida, etc).
    agresivo -> acción máxima disponible (bloqueo total, kill, reset de password).

Cada grupo de estrategia (ej. "usuario_sospechoso") vive en
`configuracion_modulos` como filas con el mismo `modulo` (nombre del grupo) y
`parametro` distinto (uno por nivel). Todas las filas del grupo existen
siempre -todos los niveles quedan "disponibles"-, pero únicamente una puede
tener `activo=True` al mismo tiempo. Activar un nivel desactiva
automáticamente a los demás del mismo grupo.

Seguridad: no todos los grupos pueden bajar a "minimo". Los grupos que
corresponden a indicios de explotación activa (ver PISO_NIVEL) tienen un
piso más alto: ni `activar_estrategia` permite configurarlos por debajo de
su piso, ni `obtener_nivel_efectivo` respetaría ese valor aunque alguien
edite la fila directamente en la base de datos. Esto evita que un atacante
(o un error del panel) desactive silenciosamente toda la respuesta
automática poniendo todo en "minimo".
"""

import logging

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import ConfiguracionModulo

logger = logging.getLogger("marandu.prevention.estrategia")

NIVELES = ("minimo", "moderado", "agresivo")
_ORDEN_NIVEL = {nivel: i for i, nivel in enumerate(NIVELES)}

# Piso de severidad por grupo: nivel mínimo que se va a EJECUTAR sin importar
# lo que diga la configuración. Ajustar con criterio del equipo de seguridad.
#
#   - Alarmas con alta probabilidad de falso positivo o que requieren
#     criterio humano -> piso "minimo", el admin puede decidir no automatizar nada.
#   - Alarmas de explotación activa o ataque en curso (exploit web, fuerza
#     bruta, DDoS, archivo sospechoso ya corriendo) -> piso "moderado",
#     nunca se puede silenciar del todo.
PISO_NIVEL = {
    "usuario_sospechoso": "minimo",
    "proceso_alto_consumo": "minimo",
    "archivo_tmp_sospechoso": "moderado",
    "web_scan_404": "minimo",
    "web_exploit_500": "moderado",
    "failed_login_multiple": "moderado",
    "smtp_brute_force": "moderado",
    "mail_queue_alta": "minimo",
    "ddos_detectado": "moderado",
    # Integración de las 3 discordancias del manual:
    "integridad_sistema": "moderado",    # Para MODIFICACION_PASSWD y MODIFICACION_SHADOW (Gravedad Crítica)
    "cron_sospechoso": "minimo",         # Para CRON_SOSPECHOSO
    "credential_stuffing": "moderado",   # Para CREDENTIAL_STUFFING (Fuerza bruta automatizada)
}


def _nivel_index(nivel: str) -> int:
    return _ORDEN_NIVEL.get(nivel, 0)


def piso_de(grupo: str) -> str:
    return PISO_NIVEL.get(grupo, "minimo")


async def obtener_estrategia_activa(session: AsyncSession, grupo: str, default: str = "moderado") -> str:
    """Devuelve el nivel actualmente CONFIGURADO (activo=True) para un grupo,
    tal cual está en BD, sin aplicar el piso. Útil para mostrar el estado en
    el panel."""
    stmt = select(ConfiguracionModulo).where(
        ConfiguracionModulo.modulo == grupo,
        ConfiguracionModulo.activo.is_(True),
    )
    resultado = await session.execute(stmt)
    fila = resultado.scalar_one_or_none()
    return fila.parametro if fila else default


async def obtener_nivel_efectivo(session: AsyncSession, grupo: str, default: str = "moderado") -> str:
    """Devuelve el nivel que REALMENTE se debe ejecutar: el configurado,
    salvo que esté por debajo del piso del grupo, en cuyo caso se usa el
    piso. Esta es la función que debe consultar el dispatcher de
    mitigación, nunca `obtener_estrategia_activa` directamente."""
    nivel_configurado = await obtener_estrategia_activa(session, grupo, default)
    piso = piso_de(grupo)
    if _nivel_index(nivel_configurado) < _nivel_index(piso):
        logger.warning(
            "Nivel configurado '%s' para grupo '%s' está por debajo del piso "
            "'%s'; se ejecuta el piso igual.",
            nivel_configurado, grupo, piso,
        )
        return piso
    return nivel_configurado


async def activar_estrategia(session: AsyncSession, grupo: str, nivel: str) -> bool:
    """
    Activa `nivel` dentro de `grupo` y desactiva cualquier otro nivel del
    mismo grupo (exclusión mutua). Pensado para invocarse desde un endpoint
    del panel web.
    """
    if nivel not in NIVELES:
        logger.warning("activar_estrategia: nivel inválido '%s' para grupo '%s'", nivel, grupo)
        return False

    piso = piso_de(grupo)
    if _nivel_index(nivel) < _nivel_index(piso):
        logger.warning(
            "activar_estrategia: intento de bajar '%s' a '%s', por debajo del "
            "piso permitido '%s'. Operación rechazada.",
            grupo, nivel, piso,
        )
        return False

    nivel_anterior = await obtener_estrategia_activa(session, grupo)

    await session.execute(
        update(ConfiguracionModulo)
        .where(ConfiguracionModulo.modulo == grupo)
        .values(activo=False)
    )
    resultado = await session.execute(
        update(ConfiguracionModulo)
        .where(ConfiguracionModulo.modulo == grupo, ConfiguracionModulo.parametro == nivel)
        .values(activo=True)
    )
    await session.commit()

    exito = resultado.rowcount > 0
    if exito:
        logger.info(
            "Cambio de estrategia: grupo=%s nivel_anterior=%s nivel_nuevo=%s",
            grupo, nivel_anterior, nivel,
        )
    return exito