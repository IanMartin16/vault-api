from typing import Generator, Optional
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import JWTError, jwt
from datetime import datetime
from uuid import UUID
import redis.asyncio as redis

from app.db.session import async_session
from app.core.config import get_settings
from app.core.crypto import CryptoService
from app.models.user import User, APIKey
from app.models.secret import Project

settings = get_settings()
security = HTTPBearer()

_redis_pool = None

async def get_redis() -> redis.Redis:
    """Get Redis connection."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )
    return _redis_pool

async def get_db() -> Generator:
    """Database session dependency."""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

def get_crypto_service() -> CryptoService:
    """Get initialized crypto service."""
    return CryptoService(settings.MASTER_ENCRYPTION_KEY)

async def get_current_user_from_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Validate JWT token and return current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=["HS256"]
        )
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
    stmt = select(User).where(User.id == UUID(user_id))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if user is None or not user.is_active:
        raise credentials_exception
    
    return user

async def get_current_user_from_api_key(
    x_api_key: str = Header(..., description="API Key for authentication"),
    db: AsyncSession = Depends(get_db)
) -> tuple[User, APIKey]:
    """Validate API key and return user."""
    from app.core.security import hash_api_key
    key_hash = hash_api_key(x_api_key)
    
    stmt = select(APIKey).where(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True
    )
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    if api_key.expires_at and api_key.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired"
        )
    
    api_key.last_used_at = datetime.utcnow()
    await db.commit()
    
    stmt = select(User).where(User.id == api_key.user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive"
        )
    
    return user, api_key

async def get_current_user(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),  # ← Agregar alias
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Flexible authentication: API key or JWT token."""
    
    # Intentar con API key primero
    if x_api_key:
        try:
            user, _ = await get_current_user_from_api_key(x_api_key, db)
            return user
        except HTTPException:
            pass  # Si falla, intentar con JWT
    
    # Intentar con JWT
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        from jose import jwt, JWTError
        from uuid import UUID
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = payload.get("sub")
            
            if user_id:
                from sqlalchemy import select
                stmt = select(User).where(User.id == UUID(user_id))
                result = await db.execute(stmt)
                user = result.scalar_one_or_none()
                
                if user and user.is_active:
                    return user
        except JWTError:
            pass
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )

async def verify_project_access(
    project_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Project:
    """Verify user has access to project."""
    stmt = select(Project).where(Project.id == project_id)
    result = await db.execute(stmt)
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )
    
    if project.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this project"
        )
    
    return project
