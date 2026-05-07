from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
import structlog

from app.api.deps import get_db, get_current_user_only
from app.models.user import User
from app.schemas.api_key import APIKeyCreate, APIKeyResponse, APIKeyWithSecret
from app.services.api_key_service import APIKeyService
from app.core.exceptions import APIKeyNotFoundError, ProjectNotFoundError

router = APIRouter()
logger = structlog.get_logger()


@router.post("", response_model=APIKeyWithSecret, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    api_key_data: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only)
):
    """
    Create a new API key.
    
    **Important:** The full API key is only shown once during creation.
    Store it securely - you won't be able to retrieve it again.
    
    **Scoping:**
    - If `project_id` is provided, key can only access that project
    - If `project_id` is null, key has global access to all user's projects
    
    **Expiration:**
    - If `expires_in_days` is provided, key expires after that many days
    - If null, key never expires
    
    **Security:**
    - API key format: `vsec_test_<random>` / vsec_live_(random)
    - Stored as HMAC-SHA256 hash with server-side pepper
    - Only prefix is stored for display
    """
    service = APIKeyService(db)
    
    try:
        api_key, raw_key = await service.create_api_key(
            user=current_user,
            name=api_key_data.name,
            expires_in_days=api_key_data.expires_in_days,
            project_id=api_key_data.project_id,
            scopes=api_key_data.scopes
        )
        
        logger.info(
            "api_key_created",
            user_id=str(current_user.id),
            key_id=str(api_key.id),
            key_prefix=api_key.key_prefix,
            project_id=str(api_key_data.project_id) if api_key_data.project_id else None
        )
        
        # Return APIKeyWithSecret (includes raw key)
        return APIKeyWithSecret(
            id=api_key.id,
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            project_id=api_key.project_id,
            scopes=api_key.scopes,
            is_active=api_key.is_active,
            created_at=api_key.created_at,
            expires_at=api_key.expires_at,
            last_used_at=api_key.last_used_at,
            api_key=raw_key  # ONLY shown during creation
        )
    
    except ProjectNotFoundError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=str(e)
        )
    
    except Exception as e:
        logger.error(
            "api_key_creation_error",
            error_type=type(e).__name__,
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the API key"
        )


@router.get("", response_model=list[APIKeyResponse])
async def list_api_keys(
    include_inactive: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only)
):
    """
    List all API keys for the current user.
    
    By default, only active keys are returned.
    Set `include_inactive=true` to also see revoked keys.
    
    **Note:** The full API key value is never returned after creation.
    Only the first 12 characters (prefix) are shown for reference.
    """
    service = APIKeyService(db)
    
    api_keys = await service.list_user_api_keys(
        user_id=current_user.id,
        include_inactive=include_inactive
    )
    
    logger.info(
        "api_keys_listed",
        user_id=str(current_user.id),
        count=len(api_keys),
        include_inactive=include_inactive
    )
    
    return api_keys


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only)
):
    """
    Revoke (deactivate) an API key.
    
    This is a soft delete - the key remains in the database but can no longer
    be used for authentication.
    
    **Important:** This action cannot be undone. The API key will immediately
    stop working for all requests.
    """
    service = APIKeyService(db)
    
    try:
        await service.revoke_api_key(
            key_id=key_id,
            user_id=current_user.id
        )
        
        logger.info(
            "api_key_revoked",
            user_id=str(current_user.id),
            key_id=str(key_id)
        )
        
        return None  # 204 No Content
    
    except APIKeyNotFoundError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=str(e)
        )
    
    except Exception as e:
        logger.error(
            "api_key_revoke_error",
            error_type=type(e).__name__,
            user_id=str(current_user.id),
            key_id=str(key_id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while revoking the API key"
        )