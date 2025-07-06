import os
import uuid
from datetime import datetime

import httpx
from dependencies import get_db

from app.models.user import Utilisateur
from fastapi import APIRouter
from fastapi import FastAPI, Depends, HTTPException, Request, status, Response
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession


from app.api.proxy import logger
from app.repositories import user_repo
from app.services.keycloak import get_oidc_config, get_current_user, require_roles, get_master_admin_token, \
    rate_limiter, validate_token

router = APIRouter( tags=["keycloak"])

def get_env_or_raise(var_name):
    value = os.getenv(var_name)
    if not value:
        raise EnvironmentError(f"Environment variable '{var_name}' is not set or empty.")
    return value

keycloak_config = {
    "server_url": get_env_or_raise("KEYCLOAK_SERVER_URL"),
    "realm": get_env_or_raise("KEYCLOAK_REALM"),
    "client_id": get_env_or_raise("KEYCLOAK_CLIENT_ID"),
    "client_secret": get_env_or_raise("KEYCLOAK_CLIENT_SECRET"),
    "callback_uri": get_env_or_raise("KEYCLOAK_CALLBACK_URI")
}


@router.get("/")
async def root():
    return {"message": "Welcome to FastAPI with Keycloak authentication"}

@router.get("/login")
async def login(request: Request):
    client_ip = request.client.host
    oidc_config = await get_oidc_config()
    if not rate_limiter.check(f"login:{client_ip}", limit=3, window=60):
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later."
        )
    auth_url = (
        f"{oidc_config['authorization_endpoint']}"
        f"?client_id={keycloak_config['client_id']}"
        f"&redirect_uri={keycloak_config['callback_uri']}"
        f"&response_type=code"
        f"&scope=openid profile email"
    )
    return RedirectResponse(auth_url)


# Callback endpoint - receives the auth code from Keycloak
@router.get("/callback")
async def callback(code: str):
    oidc_config = await get_oidc_config()

    # Exchange authorization code for tokens
    async with httpx.AsyncClient() as client:
        response = await client.post(
            oidc_config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": keycloak_config["client_id"],
                "client_secret": keycloak_config["client_secret"],
                "redirect_uri": keycloak_config["callback_uri"]
            }
        )

        if response.status_code != 200:
            return JSONResponse(
                status_code=400,
                content={"message": "Token exchange failed", "details": response.text}
            )

        tokens = response.json()

    # Create response with cookies
    redirect = RedirectResponse(url="/profile")
    redirect.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        max_age=tokens["expires_in"]
    )
    redirect.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        max_age=tokens["refresh_expires_in"]
    )
    return redirect


# Profile endpoint - shows user information
@router.get("/profile")
async def profile(request:Request,user: dict = Depends(get_current_user)):
    # client_ip = request.client.host
    # if not rate_limiter.check(f"profile:{client_ip}", limit=10, window=60):
    #     raise HTTPException(
    #         status_code=429,
    #         detail="Too many accessing requests , please try again later."
    #     )
    await refresh_token(request)

    return {
        "message": "You are authenticated",
        "user_info": {
            "id": user.get("sub"),
            "username": user.get("preferred_username"),
            "email": user.get("email"),
            "name": user.get("name"),
            "roles": user.get("realm_access", {}).get("roles", [])
        }
    }


# Admin-only endpoint
@router.get("/admin")
async def admin_only(user: dict = Depends(require_roles(["admin"]))):
    return {"message": "You have admin access", "user": user.get("preferred_username")}


# User-only endpoint
@router.get("/user")
async def user_only(user: dict = Depends(require_roles(["user"]))):
    return {"message": "You have user access", "user": user.get("preferred_username")}


# Logout endpoint
@router.get("/logout")
async def logout(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    oidc_config = await get_oidc_config()

    # Try to revoke the token at Keycloak
    if refresh_token:
        async with httpx.AsyncClient() as client:
            await client.post(
                oidc_config["end_session_endpoint"],
                data={
                    "client_id": keycloak_config["client_id"],
                    "client_secret": keycloak_config["client_secret"],
                    "refresh_token": refresh_token
                }
            )

    # Clear cookies
    response = RedirectResponse(url="/")
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response


# Token refresh endpoint
@router.get("/refresh")
async def refresh_token(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    oidc_config = await get_oidc_config()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            oidc_config["token_endpoint"],
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": keycloak_config["client_id"],
                "client_secret": keycloak_config["client_secret"]
            }
        )

        if response.status_code != 200:
            # If refresh failed, redirect to login
            redirect = RedirectResponse(url="/login")
            redirect.delete_cookie("access_token")
            redirect.delete_cookie("refresh_token")
            return redirect

        tokens = response.json()

    # Update cookies with new tokens
    redirect = RedirectResponse(url="/profile")
    redirect.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        max_age=tokens["expires_in"]
    )
    redirect.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        max_age=tokens["refresh_expires_in"]
    )
    return redirect


@router.get("/users")
async def get_users(request: Request, user: dict = Depends(require_roles(["admin"]))):
    """
    Retrieve all users from Keycloak including their roles.
    This endpoint requires admin privileges.
    """
    # Rate limiting for admin operations
    client_ip = request.client.host
    if not rate_limiter.check(f"admin_operations:{client_ip}", limit=5, window=60):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for admin operations"
        )

    # Get parameters for filtering and pagination
    max_results = request.query_params.get("max", "100")
    first_result = request.query_params.get("first", "0")
    search = request.query_params.get("search", "")
    include_roles = request.query_params.get("include_roles", "true").lower() == "true"

    try:
        max_results = int(max_results)
        first_result = int(first_result)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid pagination parameters"
        )

    # Create the admin token
    admin_token = await get_master_admin_token()

    # Construct the query parameters
    query_params = {
        "max": max_results,
        "first": first_result
    }

    if search:
        query_params["search"] = search

    # Call the Keycloak Admin API
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get users
            response = await client.get(
                f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users",
                params=query_params,
                headers={
                    "Authorization": f"Bearer {admin_token}"
                }
            )

            if response.status_code != 200:
                logger.error(f"Failed to retrieve users: {response.text}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=response.text
                )

            users_data = response.json()
            users = []

            # Get role mappings for each user if requested
            for user_data in users_data:
                attributes = user_data.get("attributes", {})
                user_id = user_data.get("id")
                user = {
                    "id": user_data.get("id"),
                    "username": user_data.get("username"),
                    "email": user_data.get("email"),
                    "prenom": user_data.get("firstName"),
                    "nom": user_data.get("lastName"),
                    "statut": attributes.get("statut", [None])[0],       # Extraire 1er élément de la liste
                    "unite": attributes.get("unite", [None])[0],
                    "telephone": attributes.get("telephone", [None])[0],
                    "fonction": attributes.get("fonction", [None])[0],
                    "created_timestamp": user_data.get("createdTimestamp")
                }

                # Fetch roles if requested
                if include_roles:
                    # Get realm roles
                    realm_roles_response = await client.get(
                        f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users/{user_id}/role-mappings/realm",
                        headers={
                            "Authorization": f"Bearer {admin_token}"
                        }
                    )

                    if realm_roles_response.status_code == 200:
                        realm_roles = realm_roles_response.json()
                        role_names = [role.get("name") for role in realm_roles]
                        user["realm_roles"] = role_names
                    else:
                        user["realm_roles"] = []
                        logger.warning(f"Failed to get realm roles for user {user_id}: {realm_roles_response.text}")

                    # Get client roles (optional - can be performance heavy with many clients)
                    # First get all clients
                    clients_response = await client.get(
                        f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/clients",
                        headers={
                            "Authorization": f"Bearer {admin_token}"
                        }
                    )

                    if clients_response.status_code == 200:
                        clients = clients_response.json()
                        client_roles = {}

                        for client_data in clients:
                            client_id = client_data.get("id")
                            client_name = client_data.get("clientId")

                            # Get user's roles for this client
                            client_roles_response = await client.get(
                                f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users/{user_id}/role-mappings/clients/{client_id}",
                                headers={
                                    "Authorization": f"Bearer {admin_token}"
                                }
                            )

                            if client_roles_response.status_code == 200:
                                roles = client_roles_response.json()
                                if roles:  # Only add non-empty role lists
                                    client_roles[client_name] = [role.get("name") for role in roles]

                        if client_roles:  # Only add if there are any client roles
                            user["client_roles"] = client_roles

                users.append(user)

            return {
                "users": users,
                "pagination": {
                    "first": first_result,
                    "max": max_results,
                    "count": len(users)
                }
            }

    except httpx.RequestError as e:
        logger.error(f"Error connecting to Keycloak: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail=str(e)
        )


@router.post("/sync-users", status_code=201)
async def sync_users_to_db(
        request: Request,
        db: AsyncSession = Depends(get_db),
        user: dict = Depends(require_roles(["admin"]))
):
    """
    Synchronise tous les utilisateurs depuis Keycloak vers la base de données locale.
    Extrait les attributs personnalisés et combine tous les rôles en une chaîne séparée par des virgules.
    """
    # Obtenir le token admin
    admin_token = await get_master_admin_token()

    # Récupérer tous les utilisateurs de Keycloak
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Récupération des utilisateurs avec pagination
            first_result = 0
            max_results = 100
            all_keycloak_users = []

            while True:
                response = await client.get(
                    f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users",
                    params={"first": first_result, "max": max_results},
                    headers={
                        "Authorization": f"Bearer {admin_token}"
                    }
                )

                if response.status_code != 200:
                    logger.error(f"Failed to retrieve users: {response.text}")
                    raise HTTPException(
                        status_code=response.status_code,
                        detail=response.text
                    )

                batch = response.json()
                if not batch:
                    break

                all_keycloak_users.extend(batch)
                first_result += max_results

                # Si le batch est plus petit que max_results, c'est qu'on a tout récupéré
                if len(batch) < max_results:
                    break

            # Récupérer tous les utilisateurs existants dans la BD locale
            local_users = await user_repo.get_utilisateurs(db, skip=0, limit=100000)
            local_user_map = {str(user.id): user for user in local_users}

            # Tenir le compte des différentes opérations
            created_count = 0
            updated_count = 0
            deactivated_count = 0

            # Traiter chaque utilisateur Keycloak
            for kc_user in all_keycloak_users:
                kc_user_id = kc_user.get("id")
                attributes = kc_user.get("attributes", {})

                # Récupérer TOUS les rôles pour cet utilisateur (realm et client)
                all_roles = []

                # Rôles du realm
                roles_response = await client.get(
                    f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users/{kc_user_id}/role-mappings/realm",
                    headers={
                        "Authorization": f"Bearer {admin_token}"
                    }
                )

                if roles_response.status_code == 200:
                    realm_roles = roles_response.json()
                    realm_role_names = [role.get("name") for role in realm_roles]
                    all_roles.extend(realm_role_names)

                # Rôles des clients
                clients_response = await client.get(
                    f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/clients",
                    headers={
                        "Authorization": f"Bearer {admin_token}"
                    }
                )

                if clients_response.status_code == 200:
                    clients = clients_response.json()

                    for client_data in clients:
                        client_id = client_data.get("id")
                        client_name = client_data.get("clientId")

                        client_roles_response = await client.get(
                            f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users/{kc_user_id}/role-mappings/clients/{client_id}",
                            headers={
                                "Authorization": f"Bearer {admin_token}"
                            }
                        )

                        if client_roles_response.status_code == 200:
                            client_roles = client_roles_response.json()
                            for role in client_roles:
                                # Préfixer les rôles des clients avec le nom du client pour éviter les conflits
                                all_roles.append(f"{client_name}:{role.get('name')}")

                # Convertir tous les rôles en une chaîne unique séparée par des virgules
                roles_string = ",".join(
                    all_roles) if all_roles else "user"  # "user" comme valeur par défaut si aucun rôle

                # Créer un modèle utilisateur pour l'insertion/mise à jour
                user_data = {
                    "prenom": kc_user.get("firstName", ""),
                    "nom": kc_user.get("lastName", ""),
                    "email": kc_user.get("email", ""),
                    "username": kc_user.get("username", ""),
                    # Extraire les attributs personnalisés, utiliser des valeurs par défaut si non présents
                    "fonction": attributes.get("fonction", ["Autre"])[0] if attributes.get("fonction") else "Autre",
                    "statut": "Active" if kc_user.get("enabled", True) else "Inactive",
                    "role": roles_string,  # Tous les rôles combinés en une chaîne
                    "unite": attributes.get("unite", ["Autre"])[0] if attributes.get("unite") else "Autre",
                    "telephone": attributes.get("telephone", [None])[0] if attributes.get("telephone") else None
                }

                # Vérifier si l'utilisateur existe déjà par ID
                if kc_user_id in local_user_map:
                    # Mettre à jour l'utilisateur existant
                    existing_user = local_user_map[kc_user_id]
                    for key, value in user_data.items():
                        setattr(existing_user, key, value)

                    # Mettre à jour le timestamp de mise à jour
                    existing_user.updatedAt = datetime.now()

                    await db.commit()
                    updated_count += 1
                else:
                    # Créer un nouvel utilisateur
                    try:
                        new_user = Utilisateur(
                            id=uuid.UUID(kc_user_id),
                            dateInscription=datetime.now(),
                            updatedAt=datetime.now(),
                            **user_data
                        )
                        db.add(new_user)
                        await db.commit()
                        created_count += 1
                    except Exception as e:
                        logger.error(f"Error creating user {kc_user.get('username')}: {str(e)}")
                        await db.rollback()

            # Marquer comme inactifs les utilisateurs qui sont dans la BD locale mais pas dans Keycloak
            keycloak_user_ids = set(kc_user.get("id") for kc_user in all_keycloak_users)
            for local_id, local_user in local_user_map.items():
                if local_id not in keycloak_user_ids and local_user.statut != "Inactive":
                    local_user.statut = "Inactive"
                    local_user.updatedAt = datetime.now()
                    await db.commit()
                    deactivated_count += 1

            return {
                "success": True,
                "message": "User synchronization completed",
                "stats": {
                    "total_keycloak_users": len(all_keycloak_users),
                    "total_local_users": len(local_users),
                    "created": created_count,
                    "updated": updated_count,
                    "deactivated": deactivated_count
                }
            }

    except Exception as e:
        logger.error(f"Error syncing users: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error syncing users: {str(e)}"
        )


# Ajoutez cette fonction à votre user_controller.py (API Gateway)

@router.get("/users/{user_id}")
async def get_user_by_id(
        user_id: str,
        include_roles: bool = True,
        current_user: dict = Depends(get_current_user)
):
    """
    Récupérer un utilisateur par son ID Keycloak avec ses rôles
    """
    # Vérification simple des permissions
    if user_id != current_user.get("sub"):
        user_roles = current_user.get("realm_access", {}).get("roles", [])
        if "admin" not in user_roles and "manager" not in user_roles:
            raise HTTPException(
                status_code=403,
                detail="Permission denied"
            )

    try:
        # Obtenir le token admin
        admin_token = await get_master_admin_token()

        # Appeler l'API Keycloak pour les données utilisateur
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users/{user_id}",
                headers={"Authorization": f"Bearer {admin_token}"}
            )

            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="User not found")

            if response.status_code != 200:
                raise HTTPException(status_code=500, detail="Error retrieving user")

            user_data = response.json()
            attributes = user_data.get("attributes", {})

            print("*******************************************")
            print(user_data)
            print("*******************************************")

            # Données de base de l'utilisateur
            formatted_user = {
                "id": user_data.get("id"),
                "username": user_data.get("username"),
                "email": user_data.get("email"),
                "prenom": user_data.get("firstName", ""),
                "nom": user_data.get("lastName", ""),
                "full_name": f"{user_data.get('firstName', '')} {user_data.get('lastName', '')}".strip(),
                "statut": attributes.get("statut", [None])[0] if attributes.get("statut") else None,
                "unite": attributes.get("unite", [None])[0] if attributes.get("unite") else None,
                "telephone": attributes.get("telephone", [None])[0] if attributes.get("telephone") else None,
                "fonction": attributes.get("fonction", [None])[0] if attributes.get("fonction") else None,
                "created_timestamp": user_data.get("createdTimestamp"),
                "enabled": user_data.get("enabled", True)
            }

            # Récupérer les rôles si demandé
            if include_roles:
                # Récupérer les rôles du realm
                realm_roles_response = await client.get(
                    f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users/{user_id}/role-mappings/realm",
                    headers={"Authorization": f"Bearer {admin_token}"}
                )

                if realm_roles_response.status_code == 200:
                    realm_roles = realm_roles_response.json()
                    formatted_user["realm_roles"] = [role.get("name") for role in realm_roles]
                else:
                    formatted_user["realm_roles"] = []
                    logger.warning(f"Failed to get realm roles for user {user_id}: {realm_roles_response.text}")

                # Récupérer les rôles des clients
                clients_response = await client.get(
                    f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/clients",
                    headers={"Authorization": f"Bearer {admin_token}"}
                )

                client_roles = {}
                if clients_response.status_code == 200:
                    clients = clients_response.json()

                    for client_data in clients:
                        client_id = client_data.get("id")
                        client_name = client_data.get("clientId")

                        # Récupérer les rôles de ce client pour cet utilisateur
                        client_roles_response = await client.get(
                            f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users/{user_id}/role-mappings/clients/{client_id}",
                            headers={"Authorization": f"Bearer {admin_token}"}
                        )

                        if client_roles_response.status_code == 200:
                            roles = client_roles_response.json()
                            if roles:  # Seulement si l'utilisateur a des rôles pour ce client
                                client_roles[client_name] = [role.get("name") for role in roles]

                formatted_user["client_roles"] = client_roles

                # Créer une liste combinée de tous les rôles pour faciliter les vérifications
                all_roles = formatted_user["realm_roles"].copy()
                for client_name, roles in client_roles.items():
                    all_roles.extend([f"{client_name}:{role}" for role in roles])
                formatted_user["all_roles"] = all_roles

            return formatted_user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving user {user_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Version rapide sans rôles pour les cas où on n'en a pas besoin
@router.get("/users/{user_id}/basic")
async def get_user_basic_info(
        user_id: str,
        current_user: dict = Depends(get_current_user)
):
    """
    Récupérer les informations de base d'un utilisateur (sans rôles)
    Plus rapide pour les cas où on n'a besoin que des infos de base
    """
    # Vérification simple des permissions
    if user_id != current_user.get("sub"):
        user_roles = current_user.get("realm_access", {}).get("roles", [])
        if "admin" not in user_roles and "manager" not in user_roles:
            raise HTTPException(
                status_code=403,
                detail="Permission denied"
            )

    try:
        # Obtenir le token admin
        admin_token = await get_master_admin_token()

        # Appeler l'API Keycloak
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{keycloak_config['server_url']}/admin/realms/{keycloak_config['realm']}/users/{user_id}",
                headers={"Authorization": f"Bearer {admin_token}"}
            )

            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="User not found")

            if response.status_code != 200:
                raise HTTPException(status_code=500, detail="Error retrieving user")

            user_data = response.json()
            attributes = user_data.get("attributes", {})

            # Retourner seulement les informations de base
            return {
                "id": user_data.get("id"),
                "username": user_data.get("username"),
                "email": user_data.get("email"),
                "prenom": user_data.get("firstName", ""),
                "nom": user_data.get("lastName", ""),
                "full_name": f"{user_data.get('firstName', '')} {user_data.get('lastName', '')}".strip(),
                "statut": attributes.get("statut", [None])[0] if attributes.get("statut") else None,
                "unite": attributes.get("unite", [None])[0] if attributes.get("unite") else None,
                "telephone": attributes.get("telephone", [None])[0] if attributes.get("telephone") else None,
                "fonction": attributes.get("fonction", [None])[0] if attributes.get("fonction") else None,
                "enabled": user_data.get("enabled", True)
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving basic user info {user_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


# auth_handlers.py - Ajoutez ces fonctions à votre user_controller.py

from pydantic import BaseModel, EmailStr
from fastapi import HTTPException, Response, Request, Depends
from fastapi.responses import JSONResponse
import secrets
import asyncio


# Modèles de données
class EmailPasswordCredentials(BaseModel):
    email: EmailStr
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class AuthResponse(BaseModel):
    success: bool
    message: str
    tokens: dict = None
    user: dict = None


# Stockage temporaire des états OAuth (en production, utilisez Redis)
oauth_states = {}


# Fonction utilitaire pour nettoyer les états expirés
async def cleanup_expired_states():
    """Nettoie les états OAuth expirés toutes les 5 minutes"""
    current_time = datetime.now().timestamp()
    expired_states = [
        state for state, data in oauth_states.items()
        if current_time - data.get("created_at", 0) > 300  # 5 minutes
    ]

    for state in expired_states:
        oauth_states.pop(state, None)

    logger.debug(f"Cleaned up {len(expired_states)} expired OAuth states")


@router.post("/auth/login-email", response_model=AuthResponse)
async def login_with_email_credentials(
        credentials: EmailPasswordCredentials,
        request: Request
):
    """
    Authentification avec email et mot de passe via Keycloak
    """
    client_ip = request.client.host

    # Rate limiting plus strict pour les tentatives de connexion
    if not rate_limiter.check(f"login_email:{client_ip}", limit=5, window=300):
        logger.warning(f"Rate limit exceeded for email login from IP: {client_ip}")
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives de connexion. Veuillez réessayer dans 5 minutes."
        )

    try:
        logger.info(f"Email login attempt for {credentials.email} from IP {client_ip}")

        # Appel à Keycloak avec Resource Owner Password Credentials Grant
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_response = await client.post(
                f"{keycloak_config['server_url']}/realms/{keycloak_config['realm']}/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": keycloak_config["client_id"],
                    "client_secret": keycloak_config["client_secret"],
                    "username": credentials.email,
                    "password": credentials.password,
                    "scope": "openid profile email"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            # Gestion des erreurs spécifiques de Keycloak
            if token_response.status_code == 401:
                logger.warning(f"Invalid credentials for {credentials.email} from IP {client_ip}")
                raise HTTPException(
                    status_code=401,
                    detail="Email ou mot de passe incorrect"
                )
            elif token_response.status_code == 400:
                error_data = token_response.json()
                error_description = error_data.get("error_description", "")

                if "disabled" in error_description.lower():
                    raise HTTPException(
                        status_code=401,
                        detail="Compte utilisateur désactivé"
                    )
                elif "locked" in error_description.lower():
                    raise HTTPException(
                        status_code=401,
                        detail="Compte utilisateur verrouillé"
                    )
                else:
                    raise HTTPException(
                        status_code=400,
                        detail="Paramètres de connexion invalides"
                    )
            elif token_response.status_code != 200:
                logger.error(f"Keycloak error during login: {token_response.status_code} - {token_response.text}")
                raise HTTPException(
                    status_code=500,
                    detail="Erreur du service d'authentification"
                )

            tokens_data = token_response.json()

            # Validation et extraction des informations utilisateur
            try:
                user_payload = await validate_token(tokens_data["access_token"])
            except Exception as e:
                logger.error(f"Token validation failed after successful login: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail="Erreur de validation du token"
                )

            # Construction de la réponse
            response_data = {
                "success": True,
                "message": "Connexion réussie",
                "tokens": {
                    "access_token": tokens_data["access_token"],
                    "refresh_token": tokens_data["refresh_token"],
                    "expires_in": tokens_data["expires_in"],
                    "refresh_expires_in": tokens_data.get("refresh_expires_in", 1800)
                },
                "user": {
                    "id": user_payload.get("sub"),
                    "username": user_payload.get("preferred_username"),
                    "email": user_payload.get("email"),
                    "name": user_payload.get("name"),
                    "roles": user_payload.get("realm_access", {}).get("roles", []),
                    "email_verified": user_payload.get("email_verified", False)
                }
            }

            logger.info(f"Successful email login for user {user_payload.get('preferred_username')} from IP {client_ip}")
            return response_data

    except HTTPException:
        raise
    except asyncio.TimeoutError:
        logger.error(f"Timeout during email login for {credentials.email}")
        raise HTTPException(
            status_code=504,
            detail="Délai d'attente du service d'authentification"
        )
    except Exception as e:
        logger.error(f"Unexpected error during email login: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Erreur interne du serveur"
        )


@router.get("/auth/login-microsoft")
async def initiate_microsoft_login(request: Request):
    """
    Initier la connexion Microsoft via Keycloak
    """
    client_ip = request.client.host

    # Rate limiting pour les tentatives Microsoft
    if not rate_limiter.check(f"login_microsoft:{client_ip}", limit=10, window=300):
        logger.warning(f"Rate limit exceeded for Microsoft login from IP: {client_ip}")
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives de connexion Microsoft"
        )

    try:
        # Nettoyer les états expirés
        await cleanup_expired_states()

        # Générer un état unique et sécurisé pour CSRF protection
        state = secrets.token_urlsafe(32)

        # Stocker l'état temporairement avec métadonnées
        oauth_states[state] = {
            "client_ip": client_ip,
            "created_at": datetime.now().timestamp(),
            "user_agent": request.headers.get("user-agent", ""),
        }

        # Construire l'URL d'authentification Microsoft via Keycloak
        auth_url = (
            f"{keycloak_config['server_url']}/realms/{keycloak_config['realm']}/protocol/openid-connect/auth"
            f"?client_id={keycloak_config['client_id']}"
            f"&redirect_uri={keycloak_config['callback_uri']}/microsoft"
            f"&response_type=code"
            f"&scope=openid profile email"
            f"&state={state}"
            f"&kc_idp_hint=microsoft"  # Hint pour rediriger vers Microsoft
        )

        logger.info(f"Microsoft login initiated for IP {client_ip} with state {state}")

        return {
            "success": True,
            "auth_url": auth_url,
            "state": state,
            "message": "Redirection vers Microsoft initiée"
        }

    except Exception as e:
        logger.error(f"Error initiating Microsoft login: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de l'initialisation de la connexion Microsoft"
        )


@router.get("/auth/callback-microsoft", response_model=AuthResponse)
async def handle_microsoft_callback(
        code: str,
        state: str,
        request: Request,
        error: str = None
):
    """
    Traiter le callback de Microsoft après authentification
    """
    client_ip = request.client.host

    try:
        # Vérifier s'il y a une erreur OAuth
        if error:
            logger.warning(f"OAuth error from Microsoft: {error} for IP {client_ip}")

            error_messages = {
                "access_denied": "Accès refusé par l'utilisateur",
                "invalid_request": "Requête invalide",
                "unauthorized_client": "Client non autorisé",
                "unsupported_response_type": "Type de réponse non supporté",
                "invalid_scope": "Portée invalide",
                "server_error": "Erreur du serveur Microsoft",
                "temporarily_unavailable": "Service Microsoft temporairement indisponible"
            }

            error_detail = error_messages.get(error, f"Erreur OAuth: {error}")
            raise HTTPException(status_code=400, detail=error_detail)

        # Vérifier la présence du code d'autorisation
        if not code:
            logger.warning(f"Missing authorization code in Microsoft callback from IP {client_ip}")
            raise HTTPException(
                status_code=400,
                detail="Code d'autorisation manquant"
            )

        # Vérifier et valider l'état OAuth pour prévenir les attaques CSRF
        if state not in oauth_states:
            logger.warning(f"Invalid or missing OAuth state {state} from IP {client_ip}")
            raise HTTPException(
                status_code=400,
                detail="État d'authentification invalide ou expiré"
            )

        stored_state = oauth_states[state]

        # Vérifier que l'état n'est pas trop ancien (5 minutes max)
        current_time = datetime.now().timestamp()
        if current_time - stored_state["created_at"] > 300:
            oauth_states.pop(state, None)
            logger.warning(f"Expired OAuth state {state} from IP {client_ip}")
            raise HTTPException(
                status_code=400,
                detail="État d'authentification expiré"
            )

        # Vérifications de sécurité supplémentaires
        if stored_state["client_ip"] != client_ip:
            oauth_states.pop(state, None)
            logger.warning(
                f"IP mismatch for OAuth state {state}: stored {stored_state['client_ip']}, received {client_ip}")
            raise HTTPException(
                status_code=400,
                detail="Validation de sécurité échouée"
            )

        # Nettoyer l'état utilisé
        oauth_states.pop(state, None)

        # Échanger le code d'autorisation contre des tokens
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_response = await client.post(
                f"{keycloak_config['server_url']}/realms/{keycloak_config['realm']}/protocol/openid-connect/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": keycloak_config["client_id"],
                    "client_secret": keycloak_config["client_secret"],
                    "redirect_uri": f"{keycloak_config['callback_uri']}/microsoft"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if token_response.status_code == 400:
                error_data = token_response.json()
                error_type = error_data.get("error", "unknown")

                if error_type == "invalid_grant":
                    raise HTTPException(
                        status_code=400,
                        detail="Code d'autorisation invalide ou expiré"
                    )
                else:
                    logger.error(f"Token exchange error: {error_data}")
                    raise HTTPException(
                        status_code=400,
                        detail="Échange de token échoué"
                    )
            elif token_response.status_code != 200:
                logger.error(f"Token exchange failed: {token_response.status_code} - {token_response.text}")
                raise HTTPException(
                    status_code=500,
                    detail="Erreur lors de l'échange de token"
                )

            tokens_data = token_response.json()

            # Validation et extraction des informations utilisateur
            try:
                user_payload = await validate_token(tokens_data["access_token"])
            except Exception as e:
                logger.error(f"Token validation failed after Microsoft callback: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail="Erreur de validation du token Microsoft"
                )

            # Construction de la réponse
            response_data = {
                "success": True,
                "message": "Connexion Microsoft réussie",
                "tokens": {
                    "access_token": tokens_data["access_token"],
                    "refresh_token": tokens_data["refresh_token"],
                    "expires_in": tokens_data["expires_in"],
                    "refresh_expires_in": tokens_data.get("refresh_expires_in", 1800)
                },
                "user": {
                    "id": user_payload.get("sub"),
                    "username": user_payload.get("preferred_username"),
                    "email": user_payload.get("email"),
                    "name": user_payload.get("name"),
                    "roles": user_payload.get("realm_access", {}).get("roles", []),
                    "email_verified": user_payload.get("email_verified", False)
                }
            }

            logger.info(
                f"Successful Microsoft login for user {user_payload.get('preferred_username')} from IP {client_ip}")
            return response_data

    except HTTPException:
        raise
    except asyncio.TimeoutError:
        logger.error(f"Timeout during Microsoft callback processing")
        raise HTTPException(
            status_code=504,
            detail="Délai d'attente lors du traitement du callback Microsoft"
        )
    except Exception as e:
        logger.error(f"Unexpected error in Microsoft callback: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Erreur interne lors du callback Microsoft"
        )


@router.post("/auth/refresh")
async def refresh_access_token(
        refresh_request: RefreshTokenRequest,
        request: Request
):
    """
    Rafraîchir le token d'accès avec le refresh token
    """
    client_ip = request.client.host

    # Rate limiting pour les rafraîchissements
    if not rate_limiter.check(f"refresh_token:{client_ip}", limit=30, window=300):
        logger.warning(f"Rate limit exceeded for token refresh from IP: {client_ip}")
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives de rafraîchissement"
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            refresh_response = await client.post(
                f"{keycloak_config['server_url']}/realms/{keycloak_config['realm']}/protocol/openid-connect/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_request.refresh_token,
                    "client_id": keycloak_config["client_id"],
                    "client_secret": keycloak_config["client_secret"]
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if refresh_response.status_code == 400:
                error_data = refresh_response.json()
                error_type = error_data.get("error", "")

                if "invalid_grant" in error_type or "expired" in error_type:
                    logger.info(f"Refresh token expired or invalid for IP {client_ip}")
                    raise HTTPException(
                        status_code=401,
                        detail="Refresh token invalide ou expiré. Veuillez vous reconnecter."
                    )
                else:
                    logger.error(f"Refresh token error: {error_data}")
                    raise HTTPException(
                        status_code=400,
                        detail="Erreur lors du rafraîchissement"
                    )
            elif refresh_response.status_code != 200:
                logger.error(f"Token refresh failed: {refresh_response.status_code} - {refresh_response.text}")
                raise HTTPException(
                    status_code=500,
                    detail="Erreur du service de rafraîchissement"
                )

            new_tokens = refresh_response.json()

            logger.debug(f"Token refreshed successfully for IP {client_ip}")

            return {
                "success": True,
                "message": "Token rafraîchi avec succès",
                "tokens": {
                    "access_token": new_tokens["access_token"],
                    "refresh_token": new_tokens.get("refresh_token", refresh_request.refresh_token),
                    "expires_in": new_tokens["expires_in"],
                    "refresh_expires_in": new_tokens.get("refresh_expires_in", 1800)
                }
            }

    except HTTPException:
        raise
    except asyncio.TimeoutError:
        logger.error(f"Timeout during token refresh")
        raise HTTPException(
            status_code=504,
            detail="Délai d'attente lors du rafraîchissement"
        )
    except Exception as e:
        logger.error(f"Unexpected error refreshing token: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Erreur interne lors du rafraîchissement"
        )


@router.post("/auth/logout")
async def logout_user(
        refresh_request: RefreshTokenRequest,
        request: Request
):
    """
    Déconnexion - révoque les tokens côté Keycloak
    """
    client_ip = request.client.host

    try:
        logger.info(f"Logout initiated from IP {client_ip}")

        # Révoquer le refresh token auprès de Keycloak
        async with httpx.AsyncClient(timeout=10.0) as client:
            revoke_response = await client.post(
                f"{keycloak_config['server_url']}/realms/{keycloak_config['realm']}/protocol/openid-connect/logout",
                data={
                    "client_id": keycloak_config["client_id"],
                    "client_secret": keycloak_config["client_secret"],
                    "refresh_token": refresh_request.refresh_token
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            # Ne pas échouer même si la révocation côté serveur échoue
            if revoke_response.status_code not in [204, 200]:
                logger.warning(
                    f"Token revocation returned status {revoke_response.status_code}: {revoke_response.text}")
            else:
                logger.debug(f"Token successfully revoked for IP {client_ip}")

            return {
                "success": True,
                "message": "Déconnexion réussie"
            }

    except asyncio.TimeoutError:
        logger.warning(f"Timeout during logout for IP {client_ip}")
        # Retourner succès même en cas de timeout
        return {
            "success": True,
            "message": "Déconnexion réussie (timeout serveur)"
        }
    except Exception as e:
        logger.warning(f"Error during logout for IP {client_ip}: {str(e)}")
        # Retourner succès même en cas d'erreur pour la sécurité
        return {
            "success": True,
            "message": "Déconnexion réussie"
        }


@router.get("/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Récupérer les informations détaillées de l'utilisateur connecté
    """
    try:
        return {
            "success": True,
            "user": {
                "id": current_user.get("sub"),
                "username": current_user.get("preferred_username"),
                "email": current_user.get("email"),
                "name": current_user.get("name"),
                "given_name": current_user.get("given_name"),
                "family_name": current_user.get("family_name"),
                "roles": current_user.get("realm_access", {}).get("roles", []),
                "client_roles": current_user.get("resource_access", {}),
                "email_verified": current_user.get("email_verified", False),
                "preferred_locale": current_user.get("locale"),
                "last_login": datetime.now().isoformat()
            }
        }
    except Exception as e:
        logger.error(f"Error getting current user info: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de la récupération des informations utilisateur"
        )


@router.get("/auth/check")
async def check_authentication_status(request: Request):
    """
    Vérifier le statut d'authentification sans lever d'exception
    Endpoint pratique pour le frontend pour vérifier l'état de connexion
    """
    try:
        # Essayer d'extraire et valider le token
        current_user = await get_current_user(request)

        return {
            "authenticated": True,
            "user": {
                "id": current_user.get("sub"),
                "username": current_user.get("preferred_username"),
                "email": current_user.get("email"),
                "roles": current_user.get("realm_access", {}).get("roles", [])
            },
            "token_valid": True
        }
    except HTTPException as e:
        # Token invalide ou manquant
        return {
            "authenticated": False,
            "user": None,
            "token_valid": False,
            "reason": "Invalid or missing token"
        }
    except Exception as e:
        logger.error(f"Error checking auth status: {str(e)}")
        return {
            "authenticated": False,
            "user": None,
            "token_valid": False,
            "reason": "Internal error"
        }


@router.get("/auth/validate")
async def validate_token_endpoint(request: Request):
    """
    Valider explicitement un token (pour les microservices ou debugging)
    """
    client_ip = request.client.host

    # Rate limiting pour les validations
    if not rate_limiter.check(f"validate_token:{client_ip}", limit=100, window=300):
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives de validation"
        )

    try:
        current_user = await get_current_user(request)

        return {
            "valid": True,
            "user": {
                "id": current_user.get("sub"),
                "username": current_user.get("preferred_username"),
                "email": current_user.get("email"),
                "roles": current_user.get("realm_access", {}).get("roles", []),
                "exp": current_user.get("exp"),
                "iat": current_user.get("iat"),
                "iss": current_user.get("iss"),
                "aud": current_user.get("aud")
            },
            "validated_at": datetime.now().isoformat()
        }
    except HTTPException as e:
        logger.warning(f"Token validation failed for IP {client_ip}: {e.detail}")
        raise HTTPException(
            status_code=401,
            detail="Token invalide"
        )
    except Exception as e:
        logger.error(f"Error validating token for IP {client_ip}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Erreur de validation du token"
        )


# Fonction utilitaire pour nettoyer périodiquement les états OAuth expirés
async def periodic_cleanup():
    """
    Fonction de nettoyage périodique des états OAuth expirés
    À appeler périodiquement (par exemple, avec un scheduler)
    """
    while True:
        try:
            await cleanup_expired_states()
            await asyncio.sleep(300)  # Nettoyer toutes les 5 minutes
        except Exception as e:
            logger.error(f"Error in periodic cleanup: {str(e)}")
            await asyncio.sleep(60)  # Retry après 1 minute en cas d'erreur


# Endpoints additionnels pour le debugging (à utiliser seulement en développement)

@router.get("/auth/debug/states")
async def debug_oauth_states(current_user: dict = Depends(require_roles(["admin"]))):
    """
    Debug: Afficher les états OAuth actifs (admin seulement)
    """
    return {
        "active_states": len(oauth_states),
        "states": {
            state: {
                "created_at": datetime.fromtimestamp(data["created_at"]).isoformat(),
                "client_ip": data["client_ip"],
                "age_seconds": datetime.now().timestamp() - data["created_at"]
            }
            for state, data in oauth_states.items()
        }
    }


@router.post("/auth/debug/cleanup")
async def debug_cleanup_states(current_user: dict = Depends(require_roles(["admin"]))):
    """
    Debug: Nettoyer manuellement les états OAuth (admin seulement)
    """
    initial_count = len(oauth_states)
    await cleanup_expired_states()
    final_count = len(oauth_states)

    return {
        "message": "Cleanup completed",
        "initial_count": initial_count,
        "final_count": final_count,
        "cleaned": initial_count - final_count
    }