from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
import structlog

from app.api.deps import get_db, get_current_user, verify_project_access, get_crypto_service
from app.models.user import User
from app.schemas.secret import (
    SecretCreate, 
    SecretUpdate, 
    SecretResponse, 
    SecretWithValue,
    SecretVersionResponse
)
from app.services.secret_service import SecretService

router = APIRouter()
logger = structlog.get_logger()


@router.post(
    "/projects/{project_id}/secrets/{key}", 
    response_model=SecretResponse,
    status_code=status.HTTP_201_CREATED
)
async def create_secret(
    project_id: UUID,
    secret: SecretCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access)
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
    - Access is audited
    """
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
            user_id=str(current_user.id)
        )
        
        return new_secret
    
    except Exception as e:
        logger.error(
            "secret_creation_failed",
            error=str(e),
            project_id=str(project_id),
            key=secret.key
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/projects/{project_id}/secrets/{key}", response_model=SecretWithValue)
async def get_secret(
    project_id: UUID,
    key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access)
):
    """
    Get a secret by key with decrypted value.
    
    **Security:**
    - Value is decrypted on-the-fly
    - Access is logged for audit
    - Updates last_accessed_at timestamp
    
    **Note:** The decrypted value is returned in the response.
    Ensure you're using HTTPS in production.
    """
    service = SecretService(db, crypto)
    
    secret = await service.get_secret(project_id, key, include_value=True)
    
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret '{key}' not found"
        )
    
    logger.info(
        "secret_accessed",
        project_id=str(project_id),
        key=key,
        user_id=str(current_user.id)
    )
    
    return secret


@router.get("/projects/{project_id}/secrets/{key}", response_model=list[SecretResponse])
async def list_secrets(
    project_id: UUID,
    skip: int = Query(0, ge=0, description="Number of secrets to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Max secrets to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access)
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
    current_user: User = Depends(get_current_user),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access)
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
    
    except Exception as e:
        logger.error(
            "secret_update_failed",
            error=str(e),
            project_id=str(project_id),
            key=key
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete(
    "/projects/{project_id}/secrets/{key}",
    status_code=status.HTTP_204_NO_CONTENT
)
async def delete_secret(
    project_id: UUID,
    key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access)
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
            detail=f"Secret '{key}' not found"
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
    current_user: User = Depends(get_current_user),
    crypto = Depends(get_crypto_service),
    _ = Depends(verify_project_access)
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
    except Exception as e:
        logger.error(
            "version_history_failed",
            error=str(e),
            project_id=str(project_id),
            key=key
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )