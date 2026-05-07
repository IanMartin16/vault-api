from typing import Generator, Optional
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import JWTError, jwt
from datetime import datetime
from uuid import UUID
import redis.asyncio as redis
import structlog

from app.db.session import async_session
from app.core.config import get_settings
from app.core.crypto import CryptoService
from app.core.auth_context import AuthContext, AuthMethod
from app.models.user import User, APIKey
from app.models.secret import Project

settings = get_settings()
security = HTTPBearer(auto_error=False)
logger = structlog.get_logger()

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
) -> tuple[User, AuthContext]:
    """Validate JWT token and return current user with auth context."""
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
        token_type: str = payload.get("type")
        
        if user_id is None:
            raise credentials_exception
        
        # CRITICAL: Validate token type is "access", not "refresh"
        if token_type != "access":
            logger.warning(
                "invalid_token_type_attempted",
                token_type=token_type,
                user_id=user_id
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type. Use access token, not refresh token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
    except JWTError as e:
        logger.warning("jwt_decode_error", error=str(e))
        raise credentials_exception
    
    stmt = select(User).where(User.id == UUID(user_id))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if user is None or not user.is_active:
        raise credentials_exception
    
    # Create AuthContext for JWT authentication
    auth_context = AuthContext(
        user_id=user.id,
        auth_method=AuthMethod.JWT,
        scopes={"*"}
    )
    
    return user, auth_context

async def get_current_user_from_api_key(
    x_api_key: str = Header(..., description="API Key for authentication"),
    db: AsyncSession = Depends(get_db)
) -> tuple[User, AuthContext]:
    """Validate API key and return user with auth context."""
    from app.core.security import hash_api_key

    clean_api_key = x_api_key.strip()
    key_hash = hash_api_key(clean_api_key)
    
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
    
    raw_scopes = api_key.scopes or ""
    scopes = {scope.strip() for scope in raw_scopes.split(",") if scope.strip()}
    
    # Create AuthContext for API key authentication
    auth_context = AuthContext(
        user_id=user.id,
        auth_method=AuthMethod.API_KEY,
        api_key_id=api_key.id,
        api_key_project_id=api_key.project_id,  # May be None (global) or specific project
        scopes=scopes 
    )
    
    return user, auth_context

async def get_current_user(
    x_api_key: Optional[str] = Header(None),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> tuple[User, AuthContext]:
    """
    Flexible authentication: API key or JWT token.
    
    Returns:
        tuple[User, AuthContext]: Authenticated user and auth context
    """
    if x_api_key:
        return await get_current_user_from_api_key(x_api_key, db)
    elif credentials:
        return await get_current_user_from_token(credentials, db)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication credentials provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user_only(
    user_and_context: tuple[User, AuthContext] = Depends(get_current_user)
) -> User:
    """
    Convenience wrapper to get only the User from authentication.
    
    Use this in endpoints that don't need AuthContext.
    Use get_current_user directly when you need AuthContext.
    """
    user, _ = user_and_context
    return user

async def verify_project_access(
    project_id: UUID,
    user_and_context: tuple[User, AuthContext] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Project:
    """
    Verify user has access to project.
    
    Validations:
    - Project exists
    - User owns the project
    - If API key authentication: API key can access this project
    """
    current_user, auth_context = user_and_context
    
    stmt = select(Project).where(Project.id == project_id)
    result = await db.execute(stmt)
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found or access denied"
        )
    
    # Verify ownership
    if project.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Project not found or access denied"
        )
    
    # CRITICAL: If using API key, verify it can access this project
    if auth_context.is_api_key_auth():
        if not auth_context.can_access_project(project_id):
            logger.warning(
                "api_key_project_access_denied",
                user_id=str(current_user.id),
                api_key_id=str(auth_context.api_key_id),
                requested_project=str(project_id),
                allowed_project=str(auth_context.api_key_project_id)
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Project not found or access denied"
            )
    
    return project

def require_scope(required_scope: str):
    async def dependency(
        user_and_context: tuple[User, AuthContext] = Depends(get_current_user)
    ) -> AuthContext:
        _, auth_context = user_and_context

        logger.warning(
            "scope_check_executed",
            required_scope=required_scope,
            auth_method=auth_context.auth_method.value,
            api_key_id=str(auth_context.api_key_id) if auth_context.api_key_id else None,
            scopes=list(auth_context.scopes),
            has_scope=auth_context.has_scope(required_scope)
        )

        if not auth_context.has_scope(required_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )

        return auth_context

    return dependency