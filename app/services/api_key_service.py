"""
API Key Service - Business logic for API key management.

Handles creation, listing, validation, and revocation of API keys.
"""

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID
import secrets

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import APIKey, User
from app.models.secret import Project
from app.schemas.api_key import ALLOWED_API_KEY_SCOPES
from app.core.exceptions import ForbiddenError
from app.core.security import hash_api_key
from app.core.exceptions import (
    APIKeyNotFoundError,
    ProjectNotFoundError,
    VaultAPIException
)


class APIKeyService:
    """Service for managing API keys."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_api_key(
        self, 
        user: User,
        name: str,
        expires_in_days: int | None = None,
        project_id: UUID | None = None,
        scopes: list[str] | None = None
    ) -> tuple[APIKey, str]:
        """
        Create a new API key.
        
        Args:
            user: User creating the key
            name: Descriptive name for the key
            expires_in_days: Optional expiration (None = never expires)
            project_id: Optional project scope (None = global access)
        
        Returns:
            tuple[APIKey, str]: (APIKey model, raw API key string)
            
        Security:
            - Raw API key is only returned once during creation
            - Stored as hash in database
            - First 12 chars stored as prefix for user reference
        """

        requested_scopes = [scope.strip() for scope in (scopes or [])]

        if not requested_scopes:
            requested_scopes = [
                "projects:read",
                "secrets:read",
                "secrets:reveal"
            ]

        invalid_scopes = [
            scope for scope in requested_scopes
            if scope not in ALLOWED_API_KEY_SCOPES
        ]

        if invalid_scopes:
            raise ForbiddenError("Invalid API key scope")

        normalized_scopes = sorted(set(requested_scopes))
        
        # Validate project_id if provided
        if project_id:
            await self._validate_project_access(user.id, project_id)
        
        # Generate API key: "vault_" + 45 random chars
        raw_key = self._generate_api_key()
        key_hash = hash_api_key(raw_key)
        key_prefix = raw_key[:12]  # "vault_abc12"
        
        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        # Create API key record
        api_key = APIKey(
            user_id=user.id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            project_id=project_id,
            expires_at=expires_at,
            scopes=",".join(normalized_scopes),
            is_active=True
        )
        
        self.db.add(api_key)
        await self.db.commit()
        await self.db.refresh(api_key)
        
        return api_key, raw_key
    
    async def list_user_api_keys(
        self,
        user_id: UUID,
        include_inactive: bool = False
    ) -> List[APIKey]:
        """
        List all API keys for a user.
        
        Args:
            user_id: User ID
            include_inactive: Whether to include revoked keys
        
        Returns:
            List of APIKey objects (without raw key values)
        """
        stmt = select(APIKey).where(APIKey.user_id == user_id)
        
        if not include_inactive:
            stmt = stmt.where(APIKey.is_active == True)
        
        stmt = stmt.order_by(APIKey.created_at.desc())
        
        result = await self.db.execute(stmt)
        return list(result.scalars().all())
    
    async def get_api_key_by_id(
        self,
        key_id: UUID,
        user_id: UUID
    ) -> Optional[APIKey]:
        """
        Get a specific API key by ID.
        
        Ensures the key belongs to the requesting user.
        """
        stmt = select(APIKey).where(
            and_(
                APIKey.id == key_id,
                APIKey.user_id == user_id
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
    
    async def revoke_api_key(
        self,
        key_id: UUID,
        user_id: UUID
    ) -> None:
        """
        Revoke (deactivate) an API key.
        
        Soft delete - marks as inactive instead of deleting.
        
        Raises:
            APIKeyNotFoundError: If key doesn't exist or doesn't belong to user
        """
        api_key = await self.get_api_key_by_id(key_id, user_id)
        
        if not api_key:
            raise APIKeyNotFoundError(f"API key not found")
        
        api_key.is_active = False
        await self.db.commit()
    
    async def update_last_used(self, api_key: APIKey) -> None:
        """
        Update last_used_at timestamp.
        
        Called automatically when API key is used for authentication.
        """
        api_key.last_used_at = datetime.utcnow()
        await self.db.commit()
    
    # Private helper methods
    
    def _generate_api_key(self, enviroment: str="test") -> str:
        """
        Generate a secure API key.
        
        Format: 
        - vsec_test_<45 random chars>
        - vsec_live_<45 randoom chars>
        
        Entropy: ~268 bits using 45 chars from a 62-character alphabet.
        """
        # Generate 45 random alphanumeric characters
        # Using secrets module (cryptographically secure)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        random_part = ''.join(secrets.choice(alphabet) for _ in range(45))

        prefix ="vsec_live" if enviroment == "production" else "vsec_test"
        
        return f"{prefix}_{random_part}"
    
    async def _validate_project_access(self, user_id: UUID, project_id: UUID) -> None:
        """
        Validate that user owns the project.
        
        Raises:
            ProjectNotFoundError: If project doesn't exist or user doesn't own it
        """
        stmt = select(Project).where(
            and_(
                Project.id == project_id,
                Project.owner_id == user_id
            )
        )
        result = await self.db.execute(stmt)
        project = result.scalar_one_or_none()
        
        if not project:
            raise ProjectNotFoundError(
                "Project not found or access denied"
            )


class APIKeyNotFoundError(VaultAPIException):
    """Raised when API key is not found."""
    def __init__(self, message: str = "API key not found"):
        super().__init__(message, 404)