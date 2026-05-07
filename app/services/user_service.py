from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from datetime import datetime, timedelta
from uuid import UUID

from app.models.user import User, APIKey
from app.models.secret import Project
from app.schemas.user import UserCreate, UserResponse
from app.schemas.api_key import (
    APIKeyCreate,
    APIKeyWithSecret,
    ALLOWED_API_KEY_SCOPES,
)
from app.core.security import (
    get_password_hash,
    verify_password,
    generate_api_key,
    hash_api_key,
)
from app.core.config import get_settings
from app.core.exceptions import (
    ForbiddenError,
    DuplicateUserError,
)

settings = get_settings()


class UserService:
    """Business logic for user management."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_user(self, user_data: UserCreate) -> User:
        """Create a new user."""
        
        # Check if email already exists
        stmt = select(User).where(User.email == user_data.email)
        result = await self.db.execute(stmt)
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            raise DuplicateUserError("User already exists")
        
        # Hash password
        hashed_password = get_password_hash(user_data.password)
        
        # Create user
        user = User(
            email=user_data.email,
            hashed_password=hashed_password,
            full_name=user_data.full_name,
            is_active=True,
            is_verified=False  # Email verification can be added later
        )
        
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        
        return user
    
    async def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """Authenticate user with email and password."""
        
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            return None
        
        if not verify_password(password, user.hashed_password):
            return None
        
        if not user.is_active:
            raise ForbiddenError("User account is inactive")
        
        # Update last login
        user.last_login = datetime.utcnow()
        await self.db.commit()
        
        return user
    
    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
    
    async def create_api_key(
        self,
        user_id: UUID,
        key_data: APIKeyCreate
    ) -> APIKeyWithSecret:
        """Create a new API key for a user."""

        if key_data.project_id is not None:
            stmt = select(Project).where(
                Project.id == key_data.project_id,
                Project.owner_id == user_id
            )
            result = await self.db.execute(stmt)
            project = result.scalar_one_or_none()

            if not project:
                raise ForbiddenError("Project not found or access denied")

        requested_scopes = [scope.strip() for scope in (key_data.scopes or [])]

        invalid_scopes = [
            scope for scope in requested_scopes
            if scope not in ALLOWED_API_KEY_SCOPES
        ]

        if invalid_scopes:
            raise ForbiddenError("Invalid API key scope")

        normalized_scopes = sorted(set(requested_scopes))
        if not normalized_scopes:
            normalized_scopes = ["projects:read", "secrets:read", "secrets:reveal"]

        api_key = generate_api_key()
        key_hash = hash_api_key(api_key)
        key_prefix = api_key[:18]  # First 18 chars for display

        expires_at = None
        if key_data.expires_in_days is not None:
            expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)

        api_key_record = APIKey(
            user_id=user_id,
            project_id=key_data.project_id,
            name=key_data.name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            expires_at=expires_at,
            scopes=",".join(normalized_scopes),
            is_active=True
        )

        self.db.add(api_key_record)
        await self.db.commit()
        await self.db.refresh(api_key_record)

        return APIKeyWithSecret(
            id=api_key_record.id,
            name=api_key_record.name,
            key_prefix=api_key_record.key_prefix,
            project_id=api_key_record.project_id,
            scopes=api_key_record.scopes,
            is_active=api_key_record.is_active,
            created_at=api_key_record.created_at,
            expires_at=api_key_record.expires_at,
            last_used_at=api_key_record.last_used_at,
            api_key=api_key
        )
    
    async def list_user_api_keys(self, user_id: UUID) -> list[APIKey]:
        """List all API keys for a user."""
        stmt = select(APIKey).where(
            APIKey.user_id == user_id,
            APIKey.is_active == True
        ).order_by(APIKey.created_at.desc())
        
        result = await self.db.execute(stmt)
        return result.scalars().all()
    
    async def revoke_api_key(self, user_id: UUID, key_id: UUID) -> bool:
        """Revoke (soft delete) an API key."""
        stmt = select(APIKey).where(
            APIKey.id == key_id,
            APIKey.user_id == user_id
        )
        result = await self.db.execute(stmt)
        api_key = result.scalar_one_or_none()
        
        if not api_key:
            return False
        
        api_key.is_active = False
        await self.db.commit()
        return True  