import os
import sys
import getpass
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# 1. Recuperamos los parámetros básicos de conexión desde el entorno
db_user = os.getenv("DB_USER", "marandu_app")
db_name = os.getenv("DB_NAME", "marandu")
db_host = os.getenv("DB_HOST", "127.0.0.1")
db_port = os.getenv("DB_PORT", "5432")

# Intentamos obtener la contraseña desde las variables de entorno del sistema
db_pass = os.getenv("DB_PASSWORD")

# 2. Si no hay contraseña en el entorno y la terminal es interactiva, la solicitamos por teclado
if not db_pass and sys.stdin.isatty():
    print(f"\n[!] Base de datos M.A.R.A.N.D.U. requiere autenticación.")
    db_pass = getpass.getpass(f"[?] Introduce la contraseña para el usuario DB '{db_user}': ")

# 3. Fail-closed: si no hay contraseña de ninguna forma, detenemos la ejecución por seguridad
if not db_pass:
    raise RuntimeError(
        "Error de autenticación: No se proporcionó la contraseña de la base de datos "
        "y el proceso no se está ejecutando en una terminal interactiva."
    )

# 4. Construimos la URL de conexión asíncrona dinámicamente
DATABASE_URL = f"postgresql+asyncpg://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    async with async_session() as session:
        yield session