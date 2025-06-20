import logging
import os
import uuid
from datetime import datetime

import httpx
from services.keycloak import refresh_token
from utils import RateLimiter

from app.models.user import Utilisateur
from dotenv import load_dotenv
import httpx
from jose import jwt, JWTError
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Request, status

from app.repositories import user_repo
from sqlalchemy.ext.asyncio import AsyncSession
from dependencies import get_db



app = FastAPI()
load_dotenv()
rate_limiter = RateLimiter()
logger = logging.getLogger(__name__)

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


async def get_oidc_config():
    if not hasattr(app.state, "oidc_config"):
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{keycloak_config['server_url']}/realms/{keycloak_config['realm']}/.well-known/openid-configuration"
            )
            app.state.oidc_config = response.json()
    return app.state.oidc_config

# Add this function to your file:
async def validate_token(token):
    # Get the JWKS if not already cached
    if not hasattr(app.state, "jwks"):
        oidc_config = await get_oidc_config()
        async with httpx.AsyncClient() as client:
            response = await client.get(oidc_config["jwks_uri"])
            app.state.jwks = response.json()

    # Extract the token header to get the key ID
    token_parts = token.split('.')
    if len(token_parts) != 3:
        raise JWTError("Invalid token format")

    # Decode the header (first part of the token)
    from jose.utils import base64url_decode
    import json

    # Convert string to bytes before decoding
    header_bytes = token_parts[0].encode('ascii')
    header = json.loads(base64url_decode(header_bytes).decode('utf-8'))
    kid = header.get("kid")

    # Find the matching key in the JWKS
    key = None
    for jwk in app.state.jwks["keys"]:
        if jwk.get("kid") == kid:
            key = jwk
            break

    if not key:
        raise JWTError(f"Key ID {kid} not found in JWKS")

    # Now properly verify the token
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=keycloak_config["client_id"],
        options={"verify_signature": True}  # Enable verification!
    )

async def get_current_user(request: Request):
    # Try to get token from cookies
    token = request.cookies.get("access_token")

    # If not found, try to get token from Authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Validate JWT
        payload = await validate_token(token)
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )


# Helper function to check if user has specific roles
def require_roles(required_roles: List[str]):
    async def role_checker(user: dict = Depends(get_current_user)):
        user_roles = user.get("realm_access", {}).get("roles", [])
        for role in required_roles:
            if role not in user_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role {role} required"
                )
        return user

    return role_checker

async def get_master_admin_token():
    """
    Get a master admin token that has permissions to access any realm's Admin API.
    This approach uses the master realm's admin credentials.
    """
    try:
        async with httpx.AsyncClient() as client:
            # Note: This uses the master realm regardless of your app's realm
            response = await client.post(
                f"{keycloak_config['server_url']}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",  # This is a special client in the master realm
                    "username": "admin",  # Use your master realm admin username
                    "password": "admin"  # Use your master realm admin password
                }
            )

            if response.status_code != 200:
                logger.error(f"Failed to get admin token: {response.text}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=response.text  # Pass through the original error
                )

            token_data = response.json()
            return token_data["access_token"]

    except Exception as e:
        logger.error(f"Error getting admin token: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)  # Pass through the actual error
        )



@app.post("/sync-users", status_code=201)
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


@app.get("/get-token")
async def get_token(request: Request) -> str:
    """
    Extract the access token from the request cookies or authorization header.
    Returns the token or raises an HTTPException if no token is found.
    """
    await refresh_token(request)
    client_ip = request.client.host
    if not rate_limiter.check(f"login:{client_ip}", limit=10, window=60):
        raise HTTPException(
            status_code=429,
            detail="Too many accessing requests , please try again later."
        )
    # First try to get token from cookies
    token = request.cookies.get("access_token")

    # If not in cookies, check authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return token


# Function to verify token validity
@app.get("/verify-token")
async def verify_token_endpoint(
    request: Request,
    token: Optional[str] = Depends(get_token)
):
    client_ip = request.client.host
    if not rate_limiter.check(f"login:{client_ip}", limit=10, window=60):
        raise HTTPException(
            status_code=429,
            detail="Too many accessing requests , please try again later."
        )
    try:
        # Retrieve OIDC config and JWKS if not already cached
        if not hasattr(app.state, "jwks"):
            oidc_config = await get_oidc_config()
            async with httpx.AsyncClient() as client:
                response = await client.get(oidc_config["jwks_uri"])
                app.state.jwks = response.json()

        # Get the public key (in production, should match 'kid' from token header)
        public_key = app.state.jwks["keys"][0]

        # Decode and validate the token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=keycloak_config["client_id"],
            options={"verify_signature": False}  # NOTE: Set to True in production!
        )

        return {
            "valid": True,
            "message": "Token is valid",
            "user": {
                "username": payload.get("preferred_username"),
                "email": payload.get("email"),
                "roles": payload.get("realm_access", {}).get("roles", []),
                "exp": payload.get("exp"),
            }
        }

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}")


