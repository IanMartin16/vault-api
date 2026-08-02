from fastapi import APIRouter

from app.api.v1 import auth, secrets, projects, api_keys, users, billing, audit, magic_link

api_router = APIRouter()

# Include all sub-routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(projects.router, prefix="/projects", tags=["Projects"])
api_router.include_router(secrets.router, tags=["Secrets"])  # Nested under projects
api_router.include_router(api_keys.router, prefix="/api-keys", tags=["API Keys"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(magic_link.router, prefix="/auth", tags=["auth"])
api_router.include_router(billing.router, prefix="/billing", tags=["billing"])
api_router.include_router(
    audit.router,
    prefix="/audit-logs",
    tags=["Audit Logs"],
)
