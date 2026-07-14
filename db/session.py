import os

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# Carga variables desde un archivo .env si python-dotenv está disponible
# (setup_env.sh genera uno con permisos 600 al crear la base de datos).
# Si el paquete no está instalado, simplemente se ignora y se depende de
# variables de entorno reales (systemd EnvironmentFile, etc).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Fail-closed: antes había un valor por defecto con una contraseña de
    # ejemplo ("PASSWORD_SEGURO") embebida en el código fuente. Se retira
    # a propósito: es preferible que la aplicación no arranque a que
    # arranque silenciosamente contra una URL de conexión débil o
    # equivocada. `setup_env.sh` genera la variable real en un archivo
    # `.env` (permisos 600, dueño 'marandu') al crear el rol y la base.
    raise RuntimeError(
        "DATABASE_URL no está configurada. Definila como variable de "
        "entorno (o en un archivo .env en el directorio del proyecto) "
        "antes de iniciar la aplicación."
    )

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    async with async_session() as session:
        yield session