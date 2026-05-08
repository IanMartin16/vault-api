from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from typing import List, Optional
from uuid import UUID
from datetime import datetime
import base64

from app.models.secret import Secret, SecretVersion, Project
from app.models.user import User
from app.schemas.secret import SecretCreate, SecretUpdate, SecretWithValue, SecretResponse
from app.core.crypto import CryptoService
from app.core.plan_limits import get_plan_limits
from app.core.config import get_settings
from app.core.exceptions import (
    SecretNotFoundError,
    ProjectNotFoundError,
    DuplicateSecretError,
    SecretLimitExceededError
)

settings = get_settings()


class SecretService:
    """Business logic for secret management."""
    
    def __init__(self, db: AsyncSession, crypto: CryptoService):
        self.db = db
        self.crypto = crypto
    
    async def create_secret(
        self, 
        project_id: UUID, 
        secret_data: SecretCreate,
        user_id: UUID
    ) -> Secret:
        """Create a new secret with encryption."""
        
        # Get project and verify it exists
        project = await self._get_project(project_id)
        
        # Check secret limit based on user's plan
        await self._check_secret_limit(project.owner_id, project_id)
        
        # Check for duplicate key in this project
        stmt = select(Secret).where(
            and_(
                Secret.project_id == project_id,
                Secret.key == secret_data.key,
                Secret.is_deleted == False
            )
        )
        result = await self.db.execute(stmt)
        existing_secret = result.scalar_one_or_none()
        
        if existing_secret:
            raise DuplicateSecretError(
                f"Secret with key '{secret_data.key}' already exists in this project"
            )
        
        # Derive DEK for this project
        dek, _ = self.crypto.derive_dek(
            str(project_id), 
            base64.b64decode(project.dek_salt)
        )
        
        # Encrypt the secret value
        encrypted = self.crypto.encrypt_secret(secret_data.value, 
                                               dek,
                                               project_id=str(project_id),
                                               secret_key=secret_data.key,
                                               version=1
                                               )
        
        # Create secret record
        secret = Secret(
            project_id=project_id,
            key=secret_data.key,
            encrypted_value=encrypted,
            description=secret_data.description,
            tags=secret_data.tags,
            version=1,
            created_by=user_id
        )
        
        self.db.add(secret)
        await self.db.commit()
        await self.db.refresh(secret)
        
        return secret
    
    async def get_secret_metadata(
        self, 
        project_id: UUID, 
        key: str
    ) -> Optional[SecretResponse]:
        """Get secret metadata without decrypting the value (safe for GET)."""
        
        stmt = select(Secret).where(
            and_(
                Secret.project_id == project_id,
                Secret.key == key,
                Secret.is_deleted == False
            )
        )
        result = await self.db.execute(stmt)
        secret = result.scalar_one_or_none()
        
        if not secret:
            return None
        
        # Return metadata only (no value)
        return SecretResponse(
            id=secret.id,
            project_id=secret.project_id,
            key=secret.key,
            description=secret.description,
            tags=secret.tags,
            version=secret.version,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
            last_accessed_at=secret.last_accessed_at
        )
    
    async def reveal_secret(
        self, 
        project_id: UUID, 
        key: str
    ) -> Optional[SecretWithValue]:
        """Reveal secret value (decrypt) - should only be called via POST."""
        
        stmt = select(Secret).where(
            and_(
                Secret.project_id == project_id,
                Secret.key == key,
                Secret.is_deleted == False
            )
        )
        result = await self.db.execute(stmt)
        secret = result.scalar_one_or_none()
        
        if not secret:
            return None
        
        # Get project to derive DEK
        project = await self._get_project(project_id)
        dek, _ = self.crypto.derive_dek(
            str(project_id),
            base64.b64decode(project.dek_salt)
        )
        
        # Decrypt the secret
        decrypted = self.crypto.decrypt_secret(
            secret.encrypted_value, 
            dek,
            project_id=str(project_id),
            secret_key=secret.key,
            version=secret.version
        )

        secret.last_accessed_at = datetime.utcnow()
        await self.db.commit()
        await self.db.refresh(secret)
        
        return SecretWithValue(
            id=secret.id,
            project_id=secret.project_id,
            key=secret.key,
            description=secret.description,
            tags=secret.tags,
            version=secret.version,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
            last_accessed_at=secret.last_accessed_at,
            value=decrypted
        )
    
    async def list_secrets(
        self,
        project_id: UUID,
        skip: int = 0,
        limit: int = 100
    ) -> List[SecretResponse]:
        """List all secrets in a project (without values for security)."""
        
        stmt = (
            select(Secret)
            .where(
                and_(
                    Secret.project_id == project_id,
                    Secret.is_deleted == False
                )
            )
            .order_by(Secret.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        
        result = await self.db.execute(stmt)
        secrets = result.scalars().all()
        
        # Return without decrypted values for security
        return [
            SecretResponse(
                id=s.id,
                project_id=s.project_id,
                key=s.key,
                description=s.description,
                tags=s.tags,
                version=s.version,
                created_at=s.created_at,
                updated_at=s.updated_at,
                last_accessed_at=s.last_accessed_at
            )
            for s in secrets
        ]
    
    async def update_secret(
        self,
        project_id: UUID,
        key: str,
        update_data: SecretUpdate,
        user_id: UUID
    ) -> Secret:
        """Update a secret and create a new version."""
        
        # Get existing secret
        stmt = select(Secret).where(
            and_(
                Secret.project_id == project_id,
                Secret.key == key,
                Secret.is_deleted == False
            )
        )
        result = await self.db.execute(stmt)
        secret = result.scalar_one_or_none()
        
        if not secret:
            raise SecretNotFoundError("Secret not found or access denied")
        
        # If value is being updated, create new version
        if update_data.value is not None:
            version = SecretVersion(
            secret_id=secret.id,
            version=secret.version,
            encrypted_value=secret.encrypted_value,
            created_by=user_id
        )
        self.db.add(version)

        project = await self._get_project(project_id)
        dek, _ = self.crypto.derive_dek(
            str(project_id),
            base64.b64decode(project.dek_salt)
        )

        new_version = secret.version + 1

        encrypted = self.crypto.encrypt_secret(
            update_data.value,
            dek,
            project_id=str(project_id),
            secret_key=secret.key,
            version=new_version
        )

        secret.encrypted_value = encrypted
        secret.version = new_version

        await self._cleanup_old_versions(secret.id)
        
        # Update metadata
        if update_data.description is not None:
            secret.description = update_data.description
        
        if update_data.tags is not None:
            secret.tags = update_data.tags
        
        await self.db.commit()
        await self.db.refresh(secret)
        
        return secret
    
    async def delete_secret(
        self,
        project_id: UUID,
        key: str
    ) -> bool:
        """Soft delete a secret."""
        
        stmt = select(Secret).where(
            and_(
                Secret.project_id == project_id,
                Secret.key == key,
                Secret.is_deleted == False
            )
        )
        result = await self.db.execute(stmt)
        secret = result.scalar_one_or_none()
        
        if not secret:
            return False
        
        # Soft delete
        secret.is_deleted = True
        await self.db.commit()
        
        return True
    
    async def get_secret_versions(
        self,
        project_id: UUID,
        key: str,
        limit: int = 10
    ) -> List[SecretVersion]:
        """Get version history of a secret."""
        
        # First get the secret to get its ID
        stmt = select(Secret).where(
            and_(
                Secret.project_id == project_id,
                Secret.key == key,
                Secret.is_deleted == False
            )
        )
        result = await self.db.execute(stmt)
        secret = result.scalar_one_or_none()
        
        if not secret:
            raise SecretNotFoundError("Secret not found or access denied")
        
        # Get versions
        stmt = (
            select(SecretVersion)
            .where(SecretVersion.secret_id == secret.id)
            .order_by(SecretVersion.created_at.desc())
            .limit(limit)
        )
        
        result = await self.db.execute(stmt)
        return result.scalars().all()
    
    async def _get_project(self, project_id: UUID) -> Project:
        """Helper to get project or raise error."""
        stmt = select(Project).where(Project.id == project_id)
        result = await self.db.execute(stmt)
        project = result.scalar_one_or_none()
        
        if not project:
            raise ProjectNotFoundError(f"Project {project_id} not found")
        
        return project
    
    async def _check_secret_limit(self, user_id: UUID, project_id: UUID) -> None:
        """Check if user has reached their secret limit."""
        
        # Get user to check plan
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            return
        
        # Count current secrets in this project
        count_stmt = select(func.count(Secret.id)).where(
            and_(
                Secret.project_id == project_id,
                Secret.is_deleted == False
            )
        )
        count_result = await self.db.execute(count_stmt)
        secret_count = count_result.scalar() or 0
        
        # Get limit based on plan
        limits = get_plan_limits(user.plan.value if hasattr(user.plan, "value") else user.plan)
        max_secrets = limits["secrets_per_project"]

        if max_secrets is None:
            return
        
        if secret_count >= max_secrets:
            raise SecretLimitExceededError(
                "Secret limit reached for your plan"
            )
    
    async def _cleanup_old_versions(self, secret_id: UUID) -> None:
        """Keep only the last N versions of a secret."""
        
        # Get all versions for this secret
        stmt = (
            select(SecretVersion)
            .where(SecretVersion.secret_id == secret_id)
            .order_by(SecretVersion.created_at.desc())
        )
        result = await self.db.execute(stmt)
        versions = result.scalars().all()
        
        # Delete versions beyond the limit
        if len(versions) > settings.MAX_SECRET_VERSIONS:
            versions_to_delete = versions[settings.MAX_SECRET_VERSIONS:]
            for version in versions_to_delete:
                await self.db.delete(version)
            