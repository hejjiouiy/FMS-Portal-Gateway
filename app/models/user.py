import uuid

from sqlalchemy import Column, String, Enum , DateTime
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import declarative_base
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from app.models.enums.enum import UserStatusEnum, FonctionEnum , UniteEnum , RoleEnum
from app.config.database import Base


class Utilisateur(Base):
    __tablename__ = "utilisateurs"
    __table_args__ = {"schema": "auth_schema"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    prenom = Column(String, nullable=False)
    nom = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    fonction = Column(String, nullable=False)
    statut = Column(String, default="Inactivated")
    role = Column(String, nullable=False , default="user")
    unite = Column(String, nullable=False)
    telephone = Column(String, nullable=True)
    dateInscription = Column(DateTime, default=datetime.now)
    updatedAt= Column(DateTime, default=datetime.now, onupdate=datetime.now)


