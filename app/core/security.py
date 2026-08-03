from datetime import datetime, timedelta
from typing import Optional
from jose import jwt
from passlib.context import CryptContext
import secrets
import hmac
import hashlib

from app.core.config import get_settings

settings = get_settings()

# Password hashing context
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__memory_cost=19456,   # 19 MiB
    argon2__time_cost=3,
    argon2__parallelism=1,
)


def get_password_hash(password: str) -> str:
    """Hash a password with Argon2id."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Check a password against a stored hash.

    Works for both Argon2id and legacy bcrypt hashes — passlib picks the right
    scheme from the hash prefix.
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Malformed hash, or one of the sentinel values used for OAuth and
        # magic-link accounts ("_oauth_disabled_", "_magic_link_disabled_").
        # Those must never verify.
        return False


def password_needs_rehash(hashed_password: str) -> bool:
    """
    True when a hash uses a deprecated scheme or outdated parameters.

    Call this after a successful verify. If it returns True, re-hash the
    plaintext you already have in hand and store the result — that's how the
    bcrypt population migrates without anyone resetting a password.
    """
    try:
        return pwd_context.needs_update(hashed_password)
    except Exception:
        return False

def create_access_token(
    subject: str, 
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.
    
    Args:
        subject: Usually the user ID
        expires_delta: Optional custom expiration time
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "access"
    }
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt

def create_refresh_token(subject: str) -> str:
    """Create a JWT refresh token with longer expiration."""
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "refresh"
    }
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt

def generate_api_key() -> str:
    """
    Generate a secure random API key.
    Format: vault_<32 random hex chars>
    """
    random_part = secrets.token_hex(settings.API_KEY_LENGTH)
    return f"vault_{random_part}"

def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for storage using HMAC-SHA256 with server-side pepper.
    """
    pepper = settings.API_KEY_PEPPER.encode("utf-8")

    return hmac.new(
        pepper,
        api_key.strip().encode("utf-8"),
        hashlib.sha256
        ).hexdigest()

def generate_secret_share_token() -> str:
    """
    Generate a token for temporary secret sharing.
    Used for one-time secret links.
    """
    return secrets.token_urlsafe(32)

def verify_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT token.
    Returns the payload if valid, None otherwise.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        return payload
    except jwt.JWTError:
        return None
