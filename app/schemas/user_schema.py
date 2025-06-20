from uuid import UUID

from pydantic import BaseModel, EmailStr
from datetime import datetime
from app.models.enums.enum import UserStatusEnum, FonctionEnum , UniteEnum , RoleEnum

class UtilisateurCreate(BaseModel):
    prenom: str
    nom: str
    email: EmailStr
    username: str
    fonction: FonctionEnum
    statut: UserStatusEnum
    role: RoleEnum
    unite: UniteEnum
    telephone: str | None = None



class UtilisateurOut(UtilisateurCreate):
    id: UUID
    dateInscription: datetime

    class Config:
        orm_mode = True
