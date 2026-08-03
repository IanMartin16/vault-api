from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

import structlog
from sqlalchemy import Boolean, Column, DateTime, String, delete, func, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()


# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------

MAX_FAILURES_PER_EMAIL = 5
MAX_FAILURES_PER_IP = 25
WINDOW_MINUTES = 15

# Lockout duration grows with how many times this account has already been
# locked out today. Index = prior lockouts; the last value repeats.
LOCKOUT_LADDER_MINUTES = [15, 60, 240, 1440]


# =============================================================================
# MODEL — append to app/models/user.py, next to MagicLinkToken
# =============================================================================

"""
class LoginAttempt(Base):
    \"\"\"One row per authentication attempt. Drives brute-force lockouts.\"\"\"
    __tablename__ = "login_attempts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True, index=True)
    succeeded = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
"""

# Then, locally:
#     alembic revision --autogenerate -m "Add login attempts"
#     alembic upgrade head


# -----------------------------------------------------------------------------
# Core checks
# -----------------------------------------------------------------------------

async def is_locked_out(
    db: AsyncSession,
    *,
    email: str,
    ip_address: Optional[str],
) -> tuple[bool, Optional[str]]:
    """
    Decide whether this attempt should be rejected before touching the password.

    Returns (locked, reason). The reason is for logs only — never send it to
    the client.
    """
    from app.models.user import LoginAttempt

    now = datetime.utcnow()

    # --- Per-account -------------------------------------------------------
    # Count failures since the last SUCCESS, not since a fixed point. A correct
    # password resets the account's exposure.
    last_success_stmt = (
        select(func.max(LoginAttempt.created_at))
        .where(LoginAttempt.email == email)
        .where(LoginAttempt.succeeded.is_(True))
    )
    last_success = (await db.execute(last_success_stmt)).scalar()

    window_start = now - timedelta(minutes=WINDOW_MINUTES)
    if last_success and last_success > window_start:
        window_start = last_success

    email_failures_stmt = (
        select(func.count())
        .select_from(LoginAttempt)
        .where(LoginAttempt.email == email)
        .where(LoginAttempt.succeeded.is_(False))
        .where(LoginAttempt.created_at >= window_start)
    )
    email_failures = (await db.execute(email_failures_stmt)).scalar() or 0

    if email_failures >= MAX_FAILURES_PER_EMAIL:
        # Escalate: how many times has this account already been locked today?
        day_start = now - timedelta(hours=24)
        day_failures_stmt = (
            select(func.count())
            .select_from(LoginAttempt)
            .where(LoginAttempt.email == email)
            .where(LoginAttempt.succeeded.is_(False))
            .where(LoginAttempt.created_at >= day_start)
        )
        day_failures = (await db.execute(day_failures_stmt)).scalar() or 0

        prior_lockouts = max(0, day_failures // MAX_FAILURES_PER_EMAIL - 1)
        ladder_index = min(prior_lockouts, len(LOCKOUT_LADDER_MINUTES) - 1)
        lockout_minutes = LOCKOUT_LADDER_MINUTES[ladder_index]

        newest_stmt = (
            select(func.max(LoginAttempt.created_at))
            .where(LoginAttempt.email == email)
            .where(LoginAttempt.succeeded.is_(False))
        )
        newest_failure = (await db.execute(newest_stmt)).scalar()

        if newest_failure and now < newest_failure + timedelta(minutes=lockout_minutes):
            return True, f"email:{email_failures}f/{lockout_minutes}m"

    # --- Per-IP ------------------------------------------------------------
    # Catches credential stuffing, where each individual account only sees one
    # or two attempts and never trips the per-account rule.
    if ip_address:
        ip_failures_stmt = (
            select(func.count())
            .select_from(LoginAttempt)
            .where(LoginAttempt.ip_address == ip_address)
            .where(LoginAttempt.succeeded.is_(False))
            .where(LoginAttempt.created_at >= now - timedelta(minutes=WINDOW_MINUTES))
        )
        ip_failures = (await db.execute(ip_failures_stmt)).scalar() or 0

        if ip_failures >= MAX_FAILURES_PER_IP:
            return True, f"ip:{ip_failures}f"

    return False, None


async def record_attempt(
    db: AsyncSession,
    *,
    email: str,
    ip_address: Optional[str],
    succeeded: bool,
) -> None:
    """Log one attempt. Cheap insert — no commit, the caller owns the transaction."""
    from app.models.user import LoginAttempt

    db.add(
        LoginAttempt(
            email=email.lower().strip(),
            ip_address=ip_address,
            succeeded=succeeded,
        )
    )


async def purge_old_attempts(db: AsyncSession, older_than_days: int = 30) -> int:
    """Trim the table. Wire into a scheduled job, or call opportunistically."""
    from app.models.user import LoginAttempt

    cutoff = datetime.utcnow() - timedelta(days=older_than_days)
    result = await db.execute(
        delete(LoginAttempt).where(LoginAttempt.created_at < cutoff)
    )
    await db.commit()
    return result.rowcount or 0


# =============================================================================
# INTEGRATION — app/api/v1/auth.py, the login endpoint
# =============================================================================
#
# Replace the body of your login handler with this shape:
#
"""
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
"""
#
# Add to the imports at the top of auth.py:
#
#     from fastapi import Request
#     from app.core.login_protection import is_locked_out, record_attempt
#     from app.core.security import password_needs_rehash
#
# =============================================================================
# ONE THING TO CHECK ON RAILWAY
# =============================================================================
#
# request.client.host behind a proxy returns the PROXY's address, not the
# caller's — every attacker would share one bucket and lock out your real
# users. Railway sets X-Forwarded-For.
#
# If you already run uvicorn with --proxy-headers, request.client.host is
# correct and there's nothing to do. Otherwise add it to the start command:
#
#     alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 \
#       --port $PORT --proxy-headers --forwarded-allow-ips='*'
#
# Verify by logging request.client.host on a request from your own machine and
# confirming it matches your public IP.
#
# =============================================================================
# MONITORING — worth a look after the attacks you've been seeing
# =============================================================================
#
#   -- Top attacking IPs in the last day
#   SELECT ip_address, COUNT(*) AS failures, COUNT(DISTINCT email) AS targets
#   FROM login_attempts
#   WHERE succeeded = false AND created_at > NOW() - INTERVAL '24 hours'
#   GROUP BY ip_address
#   ORDER BY failures DESC
#   LIMIT 20;
#
#   -- Credential stuffing: one IP, many different addresses
#   SELECT ip_address, COUNT(DISTINCT email) AS accounts_probed
#   FROM login_attempts
#   WHERE succeeded = false AND created_at > NOW() - INTERVAL '7 days'
#   GROUP BY ip_address
#   HAVING COUNT(DISTINCT email) > 5
#   ORDER BY accounts_probed DESC;
#
#   -- Accounts under sustained attack (tell these users)
#   SELECT email, COUNT(*) AS failures, MAX(created_at) AS latest
#   FROM login_attempts
#   WHERE succeeded = false AND created_at > NOW() - INTERVAL '24 hours'
#   GROUP BY email
#   HAVING COUNT(*) > 20
#   ORDER BY failures DESC;
#
# =============================================================================
