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
from app.services.keycloak import get_oidc_config, get_current_user, require_roles, get_master_admin_token, rate_limiter

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