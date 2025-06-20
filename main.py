from fastapi import FastAPI
from app.api.user_controller import router as user_router
from app.api.keycloak_controller import router as keycloak_router
from app.api.proxy import router as proxy_router



app=FastAPI()



routers = [user_router, keycloak_router, proxy_router]
for router in routers:
    app.include_router(router)
