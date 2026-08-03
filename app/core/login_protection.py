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
# -----------------------------------------------------------------------------
# Core checks
# -----------------------------------------------------------------------------

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
