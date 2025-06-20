import os
from functools import lru_cache
import logging
from fastapi import FastAPI, Depends, HTTPException, Request, status, Response
from fastapi.responses import RedirectResponse, JSONResponse
from jose import jwt, JWTError
import httpx
from typing import List, Optional
from dependencies import get_db
from utils import RateLimiter
from utils import generate_internal_token
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception
)
from app.api.user_controller import router as user_router
from app.models.user import Utilisateur
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
from datetime import datetime
from app.repositories import user_repo
from dotenv import load_dotenv


app = FastAPI()
app.include_router(user_router)
rate_limiter = RateLimiter()
load_dotenv()

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
SERVICES_MAP = os.getenv("SERVICES_MAP")


SERVICE_MAP = {
    "mission": "http://localhost:8050",
    "achat": "http://localhost:8051",
    "stock": "http://localhost:8052"
}


# Function to get OIDC configuration from Keycloak
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


# Function to verify token and extract user info
#@retry(wait=wait_exponential(), stop=stop_after_attempt(5))
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


# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to FastAPI with Keycloak authentication"}


# Login endpoint - redirects to Keycloak login page
@app.get("/login")
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
@app.get("/callback")
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
@app.get("/profile")
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
@app.get("/admin")
async def admin_only(user: dict = Depends(require_roles(["admin"]))):
    return {"message": "You have admin access", "user": user.get("preferred_username")}


# User-only endpoint
@app.get("/user")
async def user_only(user: dict = Depends(require_roles(["user"]))):
    return {"message": "You have user access", "user": user.get("preferred_username")}


# Logout endpoint
@app.get("/logout")
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
@app.get("/refresh")
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

@lru_cache(maxsize=1)
def get_static_token():
    return generate_internal_token()

# @app.get("/header-token")
# async def get_header_token(request: Request):
#     client_ip = request.client.host
#     if not rate_limiter.check(f"login:{client_ip}", limit=10, window=60):
#         raise HTTPException(
#             status_code=429,
#             detail="Too many accessing requests , please try again later."
#         )
#     # First try to get token from cookies
#     access_token = request.cookies.get("access_token")
#
#     # If not in cookies, check authorization header
#     if not access_token:
#         auth_header = request.headers.get("Authorization")
#         if auth_header and auth_header.startswith("Bearer "):
#             access_token = auth_header.split(" ")[1]
#
#     if not access_token:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="No authentication token provided",
#             headers={"WWW-Authenticate": "Bearer"}
#         )
#     token = generate_internal_token()
#     return token

# Funcction to get all users
# Get all users from Keycloak
@app.get("/users")
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




# Helper function to get a master realm admin token
# This is different from your client token and has full admin access
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




# Fonction de synchronisation des utilisateurs
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

# Function to extract the access token from request
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


# Set up logging
# Set up logging (gardez votre configuration existante)
logger = logging.getLogger(__name__)

# Fonction pour déterminer si une exception httpx doit être retentée
def is_retryable_httpx_exception(exception):
    """Détermine si une exception httpx doit être retentée"""
    if isinstance(exception, httpx.TimeoutException):
        return True
    if isinstance(exception, httpx.ConnectError):
        return True
    if isinstance(exception, httpx.HTTPStatusError):
        return exception.response.status_code in [500, 502, 503, 504]
    return False


# REMPLACEZ votre endpoint proxy par celui-ci :
@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(service: str, path: str, request: Request, user=Depends(get_current_user)):
    await refresh_token(request)
    if service not in SERVICE_MAP:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")

    url = f"{SERVICE_MAP[service]}/{path}"

    # Filter and prepare headers (gardez votre logique existante)
    headers = dict(request.headers)
    headers_to_remove = ["host", "content-length", "connection"]
    for header in headers_to_remove:
        if header in headers:
            del headers[header]

    # Add user context headers (gardez votre logique existante)
    headers["X-User-ID"] = user.get("sub", "")
    headers["X-User-Email"] = user.get("email", "")
    headers["X-User-Roles"] = ",".join(user.get("realm_access", {}).get("roles", []))
    headers["X-User-Name"] = user.get("name", "")
    # token = generate_internal_token()
    # headers["X-Internal-Gateway-Key"] = token
    auth_header = request.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header
    else:
        access_token = request.cookies.get("access_token")
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"

    method = request.method

    # Handle different content types (gardez votre logique existante)
    content = None
    if method in ["POST", "PUT", "PATCH"]:
        content_type = request.headers.get("content-type", "")
        try:
            if "application/json" in content_type:
                content = await request.json()
            elif "application/x-www-form-urlencoded" in content_type:
                form = await request.form()
                content = dict(form)
            elif "multipart/form-data" in content_type:
                form = await request.form()
                content = dict(form)
            else:
                content = await request.body()
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error parsing request body: {str(e)}"
            )

    logger.info(f"Proxying {method} request to {url}")
    print(url, headers, method, content)

    # CHANGEMENT PRINCIPAL : Appeler la nouvelle fonction avec retry
    return await make_request_with_retry(method, url, content, headers, service)


# AJOUTEZ cette nouvelle fonction avec le décorateur retry :
@retry(
    stop=stop_after_attempt(3),  # Maximum 3 tentatives
    wait=wait_exponential(multiplier=1, min=1, max=10),  # Backoff exponentiel
    retry=retry_if_exception(is_retryable_httpx_exception),
    before=lambda retry_state: logger.info(
        f"Making request attempt #{retry_state.attempt_number}"
    ),
    before_sleep=lambda retry_state: logger.warning(
        f"Request failed. Retrying in {retry_state.next_action.sleep:.2f} seconds. "
        f"Attempt {retry_state.attempt_number}/3. "
    )
)
async def make_request_with_retry(method: str, url: str, content, headers: dict, service: str):
    """Fonction qui fait la requête HTTP avec retry logic"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            logger.debug(f"Making {method} request to {url}")

            response = await client.request(
                method,
                url,
                content=content,
                headers=headers,
                follow_redirects=True
            )

            # Si le status code est 5xx, lever une exception pour déclencher le retry
            if response.status_code in [500, 502, 503, 504]:
                logger.warning(f"Received retryable status code {response.status_code} from {url}")
                raise httpx.HTTPStatusError(
                    message=f"Server error: {response.status_code}",
                    request=response.request,
                    response=response
                )

            # Return the response from the microservice
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )

    except httpx.TimeoutException as e:
        logger.error(f"Timeout error while connecting to {url}: {str(e)}")
        # Cette exception sera retentée par le décorateur
        raise

    except httpx.ConnectError as e:
        logger.error(f"Connection error while connecting to {url}: {str(e)}")
        # Cette exception sera retentée par le décorateur
        raise

    except httpx.HTTPStatusError as e:
        # Si c'est un status code retryable, on relance l'exception pour le retry
        if e.response.status_code in [500, 502, 503, 504]:
            logger.error(f"HTTP status error from {url}: {e.response.status_code}")
            raise
        else:
            # Pour les autres status codes (4xx), on ne retry pas
            logger.warning(f"Non-retryable HTTP error from {url}: {e.response.status_code}")
            return Response(
                content=e.response.content,
                status_code=e.response.status_code,
                headers=dict(e.response.headers),
                media_type=e.response.headers.get("content-type")
            )

    except Exception as e:
        # Pour toute autre exception non prévue, on ne retry pas
        logger.error(f"Unexpected error while connecting to {url}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error forwarding request to service '{service}': {str(e)}"
        )