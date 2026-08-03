from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status, Request
from app.core.login_protection import is_locked_out, record_attempt
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime
from jose import JWTError, jwt
from datetime import timedelta
import structlog

from app.api.deps import get_db
from app.schemas.user import UserCreate, UserLogin, Token
from app.models.user import User
from app.core.security import password_needs_rehash, verify_password, get_password_hash, create_access_token, create_refresh_token
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
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    email = credentials.email.lower().strip()
    client_ip = request.client.host if request.client else None

    # One message for every failure mode. Distinguishing "wrong password" from
    # "no such account" from "locked out" hands an attacker a free oracle.
    generic_failure = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Gate BEFORE hashing. Argon2id costs 64 MiB per call — letting a locked
    #    attacker reach the hash step turns this endpoint into a memory DoS.
    locked, reason = await is_locked_out(db, email=email, ip_address=client_ip)
    if locked:
        await record_attempt(db, email=email, ip_address=client_ip, succeeded=False)
        await db.commit()
        logger.warning("login_locked_out", email=email, ip=client_ip, reason=reason)
        raise generic_failure

    # 2. Look up the user
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    # 3. Verify. Hash even when the user doesn't exist, so response timing
    #    doesn't reveal which addresses are registered.
    if user is None:
        get_password_hash("timing-equalisation-dummy")
        await record_attempt(db, email=email, ip_address=client_ip, succeeded=False)
        await db.commit()
        raise generic_failure

    if not verify_password(credentials.password, user.hashed_password):
        await record_attempt(db, email=email, ip_address=client_ip, succeeded=False)
        await db.commit()
        logger.warning("login_failed", user_id=str(user.id), ip=client_ip)
        raise generic_failure

    if not user.is_active:
        await record_attempt(db, email=email, ip_address=client_ip, succeeded=False)
        await db.commit()
        raise HTTPException(status_code=403, detail="Account is inactive")

    # 4. Success — upgrade a legacy bcrypt hash while the plaintext is in scope
    if password_needs_rehash(user.hashed_password):
        user.hashed_password = get_password_hash(credentials.password)
        logger.info("password_hash_upgraded", user_id=str(user.id))

    await record_attempt(db, email=email, ip_address=client_ip, succeeded=True)
    user.last_login = datetime.utcnow()
    await db.commit()

    access_token = create_access_token(
        subject=str(user.id),
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    logger.info("user_logged_in", user_id=str(user.id), ip=client_ip)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
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

# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------

class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# -----------------------------------------------------------------------------
# Endpoint
# -----------------------------------------------------------------------------

@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Exchange a valid refresh token for a new access token.

    Called server-to-server by NextAuth's jwt callback. Also usable by any
    client that holds a refresh token.
    """
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Decode and validate the refresh token
    #    NOTE: if your codebase already has a decode helper in app/core/security.py
    #    (e.g. `decode_token`), use that instead of the inline jwt.decode below.
    try:
        claims = jwt.decode(
            payload.refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError as exc:
        logger.warning("refresh_token_decode_failed", error=str(exc))
        raise credentials_error

    # 2. Make sure this is a REFRESH token, not an access token.
    #    Without this check, an access token could be replayed to mint new ones.
    if claims.get("type") != "refresh":
        logger.warning("refresh_token_wrong_type", token_type=claims.get("type"))
        raise credentials_error

    user_id = claims.get("sub")
    if not user_id:
        raise credentials_error

    # 3. Load the user and confirm the account is still usable
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None:
        logger.warning("refresh_token_user_not_found", user_id=user_id)
        raise credentials_error

    if not user.is_active:
        logger.warning("refresh_token_inactive_user", user_id=str(user.id))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    # 4. Issue a fresh pair (rotation — the old refresh token is replaced)
    access_token = create_access_token(
        subject=str(user.id),
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    new_refresh_token = create_refresh_token(subject=str(user.id))

    logger.info("access_token_refreshed", user_id=str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )