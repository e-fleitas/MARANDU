import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import JSONB

Base = declarative_base()

class UsuarioWeb(Base):
    __tablename__ = "usuarios_web" # Convención: snake_case plural[cite: 5]

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    rol = Column(String, default="admin")
    ultimo_login = Column(DateTime, nullable=True)

class Alarma(Base):
    __tablename__ = "alarmas"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    tipo_alarma = Column(String, nullable=False) # Ej: SNIFFER_PROMISC_DETECTED[cite: 5]
    ip_origen = Column(String, nullable=True)
    modulo = Column(String, nullable=False) # Ej: modulo_iii[cite: 5]
    resuelta = Column(Boolean, default=False)
    detalle = Column(JSONB, nullable=True)

    acciones = relationship("AccionPrevencion", back_populates="alarma")

class AccionPrevencion(Base):
    __tablename__ = "acciones_prevencion"

    id = Column(Integer, primary_key=True, index=True)
    alarma_id = Column(Integer, ForeignKey("alarmas.id"), nullable=False)
    accion = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    resultado = Column(String, nullable=False) # Éxito / Fallo[cite: 5]

    alarma = relationship("Alarma", back_populates="acciones")

class ConfiguracionModulo(Base):
    __tablename__ = "configuracion_modulos"

    id = Column(Integer, primary_key=True, index=True)
    modulo = Column(String, nullable=False)
    parametro = Column(String, nullable=False)
    valor = Column(String, nullable=False)
    activo = Column(Boolean, default=True)

class EventoRaw(Base):
    __tablename__ = "eventos_raw"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    fuente = Column(String, nullable=False)  # Ej: access.log, secure, maillog
    ip_origen = Column(String, nullable=True, index=True)
    usuario = Column(String, nullable=True)
    contenido_raw = Column(String, nullable=False)
    modulo = Column(String, nullable=False)  # Ej: modulo_iv
    procesado = Column(Boolean, default=False)
