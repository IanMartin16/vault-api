from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import timedelta
import structlog

from app.api.deps import get_db
from app.schemas.user import UserCreate, UserLogin, Token
from app.models.user import User
from app.core.security import verify_password, get_password_hash, create_access_token, create_refresh_token
from app.core.config import get_settings

settings = get_settings()
logger = structlog.get_logger()
router = APIRouter()


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user.
    
    Creates a new user account and returns access/refresh tokens.
    Email must be unique.
    """
    # Check if user already exists
    stmt = select(User).where(User.email == user_data.email)
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        email=user_data.email,
        hashed_password=hashed_password,
        full_name=user_data.full_name,
        is_active=True,
        is_verified=True,  # Auto-verify for MVP (in production, send email)
        plan="free"
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    # Create tokens
    access_token = create_access_token(
        subject=str(new_user.id),
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_refresh_token(
        subject=str(new_user.id)
    )
    
    logger.info(
        "user_registered",
        user_id=str(new_user.id),
        email=new_user.email
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/login", response_model=Token)
async def login(
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Login and get access token.
    
    Validates credentials and returns JWT tokens.
    """
    # Find user
    stmt = select(User).where(User.email == credentials.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    # Validate credentials
    if not user or not verify_password(credentials.password, user.hashed_password):
        logger.warning(
            "login_failed",
            email=credentials.email,
            reason="invalid_credentials"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.is_active:
        logger.warning(
            "login_failed",
            email=credentials.email,
            user_id=str(user.id),
            reason="inactive_account"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )
    
    # Create tokens
    access_token = create_access_token(
        subject=str(user.id),
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_refresh_token(
        subject=str(user.id)
    )
    
    logger.info(
        "user_logged_in",
        user_id=str(user.id),
        email=user.email
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

class OAuthProvisionRequest(BaseModel):
    provider: Literal["github", "resend"]
    provider_account_id: str
    email: EmailStr
    name: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# -----------------------------------------------------------------------------
# Endpoint
# -----------------------------------------------------------------------------

@router.post("/oauth-provision", response_model=TokenResponse)
async def oauth_provision(
    payload: OAuthProvisionRequest,
    x_internal_auth: Annotated[Optional[str], Header(alias="X-Internal-Auth")] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Server-to-server endpoint called by NextAuth after successful OAuth.
    Not exposed to end users — protected by a shared secret in X-Internal-Auth.
    """
    # 1. Verify the shared secret (protects against unauthorized user creation)
    expected = settings.INTERNAL_PROVISION_SECRET
    if not expected or not x_internal_auth or x_internal_auth != expected:
        logger.warning(
            "oauth_provision_forbidden",
            has_header=bool(x_internal_auth),
            provider=payload.provider,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden",
        )

    # 2. Look up user by email
    stmt = select(User).where(User.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    # 3. If not found, create with an unusable password hash
    #    (OAuth users can't sign in via /auth/login with password)
    if user is None:
        user = User(
            email=payload.email,
            hashed_password="_oauth_disabled_",  # sentinel — never matches bcrypt
            full_name=payload.name or "",
            is_active=True,
            is_verified=True,  # OAuth-verified via provider
            plan="free",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        logger.info(
            "oauth_user_provisioned",
            user_id=str(user.id),
            email=user.email,
            provider=payload.provider,
        )
    else:
        logger.info(
            "oauth_user_signed_in",
            user_id=str(user.id),
            email=user.email,
            provider=payload.provider,
        )

    # 4. Guard: don't issue tokens for inactive accounts
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    # 5. Issue the SAME tokens as the password /auth/login flow
    access_token = create_access_token(
        subject=str(user.id),
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )