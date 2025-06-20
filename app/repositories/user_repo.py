from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.user import Utilisateur
from app.schemas.user_schema import UtilisateurCreate
from sqlalchemy.orm import selectinload


async def create_utilisateur(db: AsyncSession, utilisateur: UtilisateurCreate):
    db_utilisateur = Utilisateur(**utilisateur.dict())
    db.add(db_utilisateur)
    await db.commit()
    await db.refresh(db_utilisateur)
    return db_utilisateur

async def get_utilisateur_by_id(db: AsyncSession, utilisateur_id: UUID):
    result = await db.execute(select(Utilisateur).where(Utilisateur.id == utilisateur_id)
                              )
    return result.scalar_one_or_none()

async def get_utilisateurs(db: AsyncSession, skip: int = 0, limit: int =100):
    result = await db.execute(select(Utilisateur).offset(skip).limit(limit))
    return result.scalars().all()

async def delete_utilisateur(db: AsyncSession, utilisateur_id: UUID):
    result = await db.execute(select(Utilisateur).where(Utilisateur.id == utilisateur_id))
    utilisateur = result.scalar_one_or_none()
    if utilisateur:
        await db.delete(utilisateur)
        await db.commit()
    return utilisateur

async def update_utilisateur(db: AsyncSession, utilisateur_id: UUID, utilisateur: UtilisateurCreate):
    result = await db.execute(select(Utilisateur).where(Utilisateur.id == utilisateur_id))
    db_utilisateur = result.scalar_one_or_none()
    if db_utilisateur is None:
        return None;

    for key, value in utilisateur.dict(exclude_unset=True).items():
        setattr(db_utilisateur, key, value)

    await db.commit()
    await db.refresh(db_utilisateur)
    return db_utilisateur
