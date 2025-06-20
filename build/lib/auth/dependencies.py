from fastapi import Request, HTTPException, status, Depends
from jose import jwt, JWTError
import httpx

keycloak_config = {
    "server_url": "http://localhost:8070",
    "realm": "myrealm",
    "client_id": "fastapi-client",
    "client_secret": "xJYnqlqx2ghUDJWcNjW3n156BLqYt3lN"
}


class KeycloakAuth:
    def __init__(self):
        self.oidc_config = None
        self.jwks = None

    async def fetch_oidc_config(self):
        if not self.oidc_config:
            async with httpx.AsyncClient() as client:
                res = await client.get(
                    f"{keycloak_config['server_url']}/realms/{keycloak_config['realm']}/.well-known/openid-configuration"
                )
                self.oidc_config = res.json()
        return self.oidc_config

    async def fetch_jwks(self):
        if not self.jwks:
            oidc_config = await self.fetch_oidc_config()
            async with httpx.AsyncClient() as client:
                res = await client.get(oidc_config["jwks_uri"])
                self.jwks = res.json()
        return self.jwks

    async def verify_token(self, token: str):
        jwks = await self.fetch_jwks()
        try:
            public_key = jwks["keys"][0]  # For production: use 'kid' to find correct key
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=keycloak_config["client_id"],
                options={"verify_signature": False}  # ⚠️ Should be True in production
            )
            return payload
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )


keycloak_auth = KeycloakAuth()


async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    return await keycloak_auth.verify_token(token)

async def get_access_token():
    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"{keycloak_config['server_url']}/realms/{keycloak_config['realm']}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": keycloak_config["client_id"],
                "client_secret": keycloak_config["client_secret"]
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        return res.json()["access_token"]


def require_roles(required_roles: list):
    async def role_checker(user: dict = Depends(get_current_user)):
        roles = user.get("realm_access", {}).get("roles", [])
        for role in required_roles:
            if role not in roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role {role} required"
                )
        return user
    return role_checker
