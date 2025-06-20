from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories import user_repo
from app.schemas.user_schema import UtilisateurCreate, UtilisateurOut
from dependencies import get_db

router = APIRouter(prefix="/utilisateur", tags=["utilisateurs"])

@router.get("/")
async def get_utilisateur( db: AsyncSession = Depends(get_db)):
    return await user_repo.get_utilisateurs(db)

@router.get("/{utilisateur_id}")
async def get_utilisateur_by_id( utilisateur_id: UUID, db: AsyncSession = Depends(get_db)):
    utilisateur = await user_repo.get_utilisateur_by_id(db, utilisateur_id)
    if utilisateur is None:
        raise HTTPException(404,"utilisateur not found")
    return utilisateur

@router.post("/add", response_model=UtilisateurOut)
async def create_utilisateur(utilisateur : UtilisateurCreate, db: AsyncSession = Depends(get_db)):
    return await user_repo.create_utilisateur(db, utilisateur)

@router.put("/update-{utilisateur_id}", response_model=UtilisateurOut)
async def update_utilisateur(
    utilisateur_id: UUID,
    utilisateur_update: UtilisateurCreate,
    db: AsyncSession = Depends(get_db)
):
    db_utilisateur = await user_repo.update_utilisateur(db, utilisateur_id, utilisateur_update)
    if db_utilisateur is None:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    return db_utilisateur

@router.delete("/delete/{utilisateur_id}", response_model=UtilisateurOut)
async def delete_utilisateur(
        utilisateur_id: UUID,
        db: AsyncSession = Depends(get_db)
):
    db_utilisateur = await user_repo.delete_utilisateur(db, utilisateur_id)
    if db_utilisateur is None:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    return db_utilisateur

