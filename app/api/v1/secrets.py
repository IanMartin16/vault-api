from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
import structlog

from app.api.deps import get_db, get_current_user, get_current_user_only, verify_project_access, get_crypto_service
from app.models.user import User
from app.schemas.secret import (
    SecretCreate, 
    SecretUpdate, 
    SecretResponse, 
    SecretWithValue,
    SecretVersionResponse
)
from app.services.secret_service import SecretService
from app.api.deps import require_scope, enforce_rate_limit
from app.core.exceptions import (
    DuplicateSecretError,
    SecretLimitExceededError,
    ProjectNotFoundError,
    SecretNotFoundError
)

router = APIRouter()
logger = structlog.get_logger()


@router.post(
    "/projects/{project_id}/secrets", 
    response_model=SecretResponse,
    status_code=status.HTTP_201_CREATED
)
async def create_secret(
    project_id: UUID,
    secret: SecretCreate,
    db: AsyncSession = Depends(get_db),
    user_and_context: tuple = Depends(get_current_user),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access),
    __ = Depends(require_scope("secrets:write")),
    ___ = Depends(enforce_rate_limit)
):
    """
    Create a new secret with AES-256-GCM encryption.
    
    The secret value is encrypted using a project-specific key derived from
    the master encryption key. The encrypted value is stored as JSONB
    containing the ciphertext and nonce.
    
    **Limits by plan:**
    - Free: 50 secrets per project
    - Starter: 200 secrets per project
    - Pro: 1,000 secrets per project
    - Enterprise: Unlimited
    
    **Security:**
    - Value is encrypted before storage
    - Never logged in plaintext
    - Access is audited with auth method
    """
    
    current_user, auth_context = user_and_context
    service = SecretService(db, crypto)
    
    try:
        new_secret = await service.create_secret(
            project_id,
            secret,
            current_user.id
        )
        
        logger.info(
            "secret_created",
            secret_id=str(new_secret.id),
            project_id=str(project_id),
            key=new_secret.key,
            user_id=str(current_user.id),
            auth_method=auth_context.auth_method.value,
            api_key_id=str(auth_context.api_key_id) if auth_context.api_key_id else None
        )
        
        return new_secret
    
    except (DuplicateSecretError, SecretLimitExceededError, ProjectNotFoundError) as e:
        # Expected errors: return specific message
        logger.warning(
            "secret_creation_failed",
            error_type=type(e).__name__,
            project_id=str(project_id),
            key=secret.key,
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=e.status_code,
            detail=str(e)
        )
    
    except Exception as e:
        # Unexpected errors: log but don't expose details
        logger.error(
            "secret_creation_error",
            error_type=type(e).__name__,
            project_id=str(project_id),
            key=secret.key,
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the secret. Please try again."
        )


@router.get("/projects/{project_id}/secrets/{key}", response_model=SecretResponse)
async def get_secret_metadata(
    project_id: UUID,
    key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access),
    __ = Depends(require_scope("secrets:read")),
    ___ = Depends(enforce_rate_limit)
):
    """
    Get secret metadata (without decrypted value).
    
    **Safe for GET:** Returns only metadata, no sensitive values.
    Use POST /reveal to get the decrypted value.
    
    **Returns:**
    - Key, description, tags, version
    - Timestamps (created, updated, last accessed)
    - NO decrypted value
    """
    service = SecretService(db, crypto)
    
    secret = await service.get_secret_metadata(project_id, key)
    
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found or access denied"
        )
    
    logger.info(
        "secret_metadata_accessed",
        project_id=str(project_id),
        key=key,
        user_id=str(current_user.id)
    )
    
    return secret


@router.post("/projects/{project_id}/secrets/{key}/reveal", response_model=SecretWithValue)
async def reveal_secret(
    project_id: UUID,
    key: str,
    db: AsyncSession = Depends(get_db),
    user_and_context: tuple = Depends(get_current_user),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access),
    __ = Depends(require_scope("secrets:reveal")),
    ___ = Depends(enforce_rate_limit)
):
    """
    Reveal secret value (decrypted).
    
    **Security:**
    - POST method prevents value from appearing in logs/history
    - Value is decrypted on-the-fly
    - Access is logged in audit trail with auth method
    - Updates last_accessed_at timestamp
    
    **IMPORTANT:** Use HTTPS in production. The decrypted value is returned
    in the response body.
    """
    
    current_user, auth_context = user_and_context
    service = SecretService(db, crypto)
    
    secret = await service.reveal_secret(project_id, key)
    
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found or access denied"
        )
    
    # Enhanced logging with auth method
    logger.info(
        "secret_revealed",
        project_id=str(project_id),
        key=key,
        user_id=str(current_user.id),
        auth_method=auth_context.auth_method.value,  # JWT or API_KEY
        api_key_id=str(auth_context.api_key_id) if auth_context.api_key_id else None,
        version=secret.version
    )
    
    return secret


@router.get("/projects/{project_id}/secrets", response_model=list[SecretResponse])
async def list_secrets(
    project_id: UUID,
    skip: int = Query(0, ge=0, description="Number of secrets to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Max secrets to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access),
    __ = Depends(require_scope("secrets:read"))
):
    """
    List all secrets in a project.
    
    **Security:** Returns metadata only (no decrypted values).
    Use GET /secrets/{key} to retrieve individual secret values.
    
    Returns secrets ordered by creation date (newest first).
    """
    service = SecretService(db, crypto)
    secrets = await service.list_secrets(project_id, skip, limit)
    return secrets


@router.put("/projects/{project_id}/secrets/{key}", response_model=SecretResponse)
async def update_secret(
    project_id: UUID,
    key: str,
    secret_update: SecretUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access),
    __ = Depends(require_scope("secrets:write")),
    ___ = Depends(enforce_rate_limit)
):
    """
    Update a secret.
    
    **Versioning:**
    - If the value is updated, the old value is archived as a version
    - Version number is incremented
    - Old versions are kept (configurable limit)
    
    **Security:**
    - New value is encrypted before storage
    - Old version is preserved for audit/rollback
    
    All fields are optional - only provided fields will be updated.
    """
    service = SecretService(db, crypto)
    
    try:
        updated_secret = await service.update_secret(
            project_id,
            key,
            secret_update,
            current_user.id
        )
        
        logger.info(
            "secret_updated",
            project_id=str(project_id),
            key=key,
            new_version=updated_secret.version,
            user_id=str(current_user.id)
        )
        
        return updated_secret
    
    except (SecretNotFoundError, ProjectNotFoundError) as e:
        # Expected errors: return specific message
        logger.warning(
            "secret_update_failed",
            error_type=type(e).__name__,
            project_id=str(project_id),
            key=key,
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=e.status_code,
            detail=str(e)
        )
    
    except Exception as e:
        # Unexpected errors: log but don't expose details
        logger.error(
            "secret_update_error",
            error_type=type(e).__name__,
            project_id=str(project_id),
            key=key,
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the secret. Please try again."
        )


@router.delete(
    "/projects/{project_id}/secrets/{key}",
    status_code=status.HTTP_204_NO_CONTENT
)
async def delete_secret(
    project_id: UUID,
    key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access),
    __ = Depends(require_scope("secrets:delete")),
    ___ = Depends(enforce_rate_limit)
):
    """
    Delete a secret (soft delete).
    
    The secret is marked as deleted but remains in the database for audit purposes.
    It will not appear in listings and cannot be retrieved.
    
    **Note:** This operation cannot be undone via the API.
    Contact support if you need to recover a deleted secret.
    """
    service = SecretService(db, crypto)
    
    deleted = await service.delete_secret(project_id, key)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found or access denied"
        )
    
    logger.warning(
        "secret_deleted",
        project_id=str(project_id),
        key=key,
        user_id=str(current_user.id)
    )


@router.get(
    "/projects/{project_id}/secrets/{key}/versions",
    response_model=list[SecretVersionResponse]
)
async def get_secret_versions(
    project_id: UUID,
    key: str,
    limit: int = Query(10, ge=1, le=100, description="Max versions to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access),
    __ = Depends(require_scope("secrets:read"))
):
    """
    Get version history of a secret.
    
    Returns up to N previous versions (default 10).
    Versions are ordered by creation date (newest first).
    
    **Note:** Version values are not decrypted in this endpoint.
    """
    service = SecretService(db, crypto)
    
    try:
        versions = await service.get_secret_versions(project_id, key, limit)
        return versions
    
    except SecretNotFoundError as e:
        # Expected error: safe to show message
        logger.warning(
            "version_history_failed",
            error_type=type(e).__name__,
            project_id=str(project_id),
            key=key
        )
        raise HTTPException(
            status_code=e.status_code,
            detail=str(e)
        )
    
    except Exception as e:
        # Unexpected errors: log but don't expose details
        logger.error(
            "version_history_error",
            error_type=type(e).__name__,
            project_id=str(project_id),
            key=key
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving version history. Please try again."
        )