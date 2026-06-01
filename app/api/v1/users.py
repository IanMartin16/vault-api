from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import structlog

from app.api.deps import get_db, get_current_user, get_current_user_only
from app.core.plan_limits import get_plan_limits
from app.models.user import User, APIKey
from app.models.secret import Project
from app.models.secret import Secret
from app.schemas.user import UserResponse
from app.schemas.api_key import APIKeyCreate, APIKeyResponse, APIKeyWithSecret
from app.services.api_key_service import APIKeyService
from app.services.user_service import UserService
from uuid import UUID

router = APIRouter()
logger = structlog.get_logger()

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user_only),
    db: AsyncSession = Depends(get_db),
):
    """
    Get current user profile.

    Returns information about the authenticated user including:
    - Email
    - Full name
    - Account status
    - Plan tier
    - Registration date
    - Plan limits
    - Current usage
    """
    logger.info(
        "user_profile_accessed",
        user_id=str(current_user.id)
    )

    limits = get_plan_limits(current_user.plan)

    projects_count_result = await db.execute(
        select(func.count(Project.id)).where(Project.owner_id == current_user.id)
    )
    projects_count = projects_count_result.scalar_one()

    secrets_count_result = await db.execute(
        select(func.count(Secret.id))
        .join(Project, Secret.project_id == Project.id)
        .where(Project.owner_id == current_user.id)
    )
    secrets_count = secrets_count_result.scalar_one()

    api_keys_count_result = await db.execute(
        select(func.count(APIKey.id)).where(APIKey.user_id == current_user.id, APIKey.is_active.is_(True)
                                            )
    )
    api_keys_count = api_keys_count_result.scalar_one()

    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified,
        "plan": current_user.plan,
        "created_at": current_user.created_at,
        "limits": {
            "projects": limits.get("projects"),
            "secrets_per_project": limits.get("secrets_per_project"),
            "api_keys": limits.get("api_keys"),
            "requests_per_minute": limits.get("requests_per_minute"),
            "monthly_requests": limits.get("monthly_requests"),
        },
        "usage": {
            "projects": projects_count,
            "secrets": secrets_count,
            "api_keys": api_keys_count,
        },
    }


@router.post("/me/api-keys", response_model=APIKeyWithSecret, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_user_only),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new API key.
    
    **IMPORTANT**: The API key is only shown once. Save it securely!
    """
    service = UserService(db)
    api_key = await service.create_api_key(current_user.id, key_data)
    return api_key


@router.get("/me/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(
    current_user: User = Depends(get_current_user_only),
    db: AsyncSession = Depends(get_db)
):
    """List all API keys for current user."""
    service = UserService(db)
    keys = await service.list_user_api_keys(current_user.id)
    return keys


@router.delete("/me/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: UUID,
    current_user: User = Depends(get_current_user_only),
    db: AsyncSession = Depends(get_db)
):
    """Revoke an API key."""
    service = APIKeyService(db)
    revoked = await service.revoke_api_key(key_id=key_id, user_id=current_user.id)
    
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )