import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# Reemplazar con las variables de entorno correspondientes en producción[cite: 5]
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://marandu_app:PASSWORD_SEGURO@127.0.0.1:5432/postgres")

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with async_session() as session:
        yield session