from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.api.deps import get_db, get_current_user, get_current_user_only
from app.models.user import User
from app.schemas.user import UserResponse
from app.schemas.api_key import APIKeyCreate, APIKeyResponse, APIKeyWithSecret
from app.services.api_key_service import APIKeyService
from app.services.user_service import UserService
from uuid import UUID

router = APIRouter()
logger = structlog.get_logger()

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user_only)
):
    """
    Get current user profile.
    
    Returns information about the authenticated user including:
    - Email
    - Full name
    - Account status (active, verified)
    - Plan tier (free, pro, enterprise)
    - Registration date
    """
    logger.info(
        "user_profile_accessed",
        user_id=str(current_user.id)
    )
    
    return current_user


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
    revoked = await service.revoke_api_key(current_user.id, key_id)
    
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )