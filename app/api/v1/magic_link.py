import hashlib
import secrets as py_secrets
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, DateTime, String, func, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import get_settings
from app.core.security import create_access_token, create_refresh_token

settings = get_settings()
logger = structlog.get_logger()

router = APIRouter()

TOKEN_TTL_MINUTES = 15
MAX_REQUESTS_PER_EMAIL = 3      # within the window below
MAX_REQUESTS_PER_IP = 10
RATE_WINDOW_MINUTES = 15

# =============================================================================
# Helpers
# =============================================================================

def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


async def _count_recent(
    db: AsyncSession, *, email: Optional[str] = None, ip: Optional[str] = None
) -> int:
    window_start = datetime.utcnow() - timedelta(minutes=RATE_WINDOW_MINUTES)
    stmt = select(func.count()).select_from(MagicLinkToken).where(
        MagicLinkToken.created_at >= window_start
    )
    if email:
        stmt = stmt.where(MagicLinkToken.email == email)
    if ip:
        stmt = stmt.where(MagicLinkToken.request_ip == ip)

    result = await db.execute(stmt)
    return result.scalar() or 0


async def _send_magic_link_email(email: str, raw_token: str) -> bool:
    """Send the sign-in link through Resend. Returns False on failure."""
    if not settings.RESEND_API_KEY:
        logger.error("resend_not_configured")
        return False

    link = f"{settings.FRONTEND_URL}/auth/verify/{raw_token}"

    html = f"""<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
      <tr>
        <td align="center">
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="max-width:480px;background:#ffffff;border-radius:12px;padding:40px;">
            <tr>
              <td style="padding-bottom:8px;font-size:13px;letter-spacing:0.08em;
                         text-transform:uppercase;color:#a9832e;font-weight:600;">
                V-Secrets
              </td>
            </tr>
            <tr>
              <td style="padding-bottom:16px;font-size:22px;font-weight:600;color:#18181b;">
                Sign in to your console
              </td>
            </tr>
            <tr>
              <td style="padding-bottom:28px;font-size:15px;line-height:1.6;color:#52525b;">
                Click the button below to sign in. This link expires in
                {TOKEN_TTL_MINUTES} minutes and can only be used once.
              </td>
            </tr>
            <tr>
              <td style="padding-bottom:28px;">
                <a href="{link}"
                   style="display:inline-block;background:#c89b3c;color:#1a1200;
                          text-decoration:none;padding:13px 28px;border-radius:8px;
                          font-weight:600;font-size:15px;">
                  Sign in to V-Secrets
                </a>
              </td>
            </tr>
            <tr>
              <td style="padding-bottom:20px;font-size:13px;line-height:1.6;color:#71717a;">
                If the button doesn't work, paste this into your browser:<br>
                <span style="color:#a1a1aa;word-break:break-all;font-size:12px;">{link}</span>
              </td>
            </tr>
            <tr>
              <td style="padding-top:20px;border-top:1px solid #e4e4e7;
                         font-size:12.5px;line-height:1.6;color:#a1a1aa;">
                If you didn't request this, you can ignore this email — nobody can
                access your account without clicking the link above.
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"""

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {settings.RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": settings.MAGIC_LINK_FROM,
                    "to": [email],
                    "subject": "Sign in to V-Secrets",
                    "html": html,
                },
            )

        if response.status_code >= 400:
            logger.error(
                "resend_send_failed",
                status=response.status_code,
                body=response.text[:400],
            )
            return False

        return True

    except Exception as exc:
        logger.error("resend_network_error", error=str(exc))
        return False


# =============================================================================
# POST /auth/magic-link/request
# =============================================================================

@router.post("/magic-link/request", status_code=status.HTTP_202_ACCEPTED)
async def request_magic_link(
    payload: MagicLinkRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Email a one-time sign-in link.

    Always responds 202 with the same body. Rate limits, unknown addresses, and
    provider failures are logged server-side but never surfaced — otherwise the
    response becomes a way to test whether an address has an account.
    """
    email = payload.email.lower().strip()
    client_ip = request.client.host if request.client else None

    uniform_response = {"status": "sent"}

    # --- Rate limits -------------------------------------------------------
    email_count = await _count_recent(db, email=email)
    if email_count >= MAX_REQUESTS_PER_EMAIL:
        logger.warning("magic_link_rate_limited", scope="email", email=email)
        return uniform_response

    if client_ip:
        ip_count = await _count_recent(db, ip=client_ip)
        if ip_count >= MAX_REQUESTS_PER_IP:
            logger.warning("magic_link_rate_limited", scope="ip", ip=client_ip)
            return uniform_response

    # --- Mint the token ----------------------------------------------------
    # 32 bytes url-safe ≈ 256 bits. Not guessable, not brute-forceable within
    # the 15 minute window.
    raw_token = py_secrets.token_urlsafe(32)

    token = MagicLinkToken(
        email=email,
        token_hash=_hash_token(raw_token),
        expires_at=datetime.utcnow() + timedelta(minutes=TOKEN_TTL_MINUTES),
        request_ip=client_ip,
    )
    db.add(token)
    await db.commit()

    sent = await _send_magic_link_email(email, raw_token)

    logger.info("magic_link_requested", email=email, sent=sent, ip=client_ip)

    return uniform_response


# =============================================================================
# POST /auth/magic-link/verify
# =============================================================================

@router.post("/magic-link/verify", response_model=TokenResponse)
async def verify_magic_link(
    payload: MagicLinkVerify,
    db: AsyncSession = Depends(get_db),
):
    """
    Redeem a sign-in link and return the usual token pair.

    Called server-to-server by NextAuth's magic-link Credentials provider.
    """
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="This sign-in link is invalid or has expired.",
    )

    # Look up by hash — the raw token is never stored, so there is nothing to
    # compare in constant time here.
    stmt = select(MagicLinkToken).where(
        MagicLinkToken.token_hash == _hash_token(payload.token)
    )
    result = await db.execute(stmt)
    token = result.scalar_one_or_none()

    if token is None:
        logger.warning("magic_link_unknown_token")
        raise invalid

    if token.consumed_at is not None:
        # A second redemption means the link was forwarded, or intercepted and
        # used before the owner got to it. Worth surfacing in the logs.
        logger.warning(
            "magic_link_replay_attempt",
            email=token.email,
            consumed_at=token.consumed_at.isoformat(),
        )
        raise invalid

    if token.expires_at < datetime.utcnow():
        logger.info("magic_link_expired", email=token.email)
        raise invalid

    # Burn it before issuing anything, so a concurrent request can't reuse it.
    token.consumed_at = datetime.utcnow()

    # --- Find or create the account ---------------------------------------
    user_stmt = select(User).where(User.email == token.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()

    if user is None:
        # First sign-in via magic link doubles as signup. The account is
        # created only now, on redemption — requesting a link for an address
        # that never clicks it leaves no user behind.
        user = User(
            email=token.email,
            hashed_password="_magic_link_disabled_",  # never matches bcrypt
            full_name="",
            is_active=True,
            is_verified=True,  # they proved control of the inbox
            plan="free",
        )
        db.add(user)
        await db.flush()
        logger.info("magic_link_user_created", email=token.email, user_id=str(user.id))

    if not user.is_active:
        await db.commit()  # keep the token consumed
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    await db.commit()

    access_token = create_access_token(
        subject=str(user.id),
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    logger.info("magic_link_redeemed", user_id=str(user.id), email=user.email)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


# =============================================================================
# Cleanup — expired and consumed tokens are dead weight
# =============================================================================

async def purge_stale_magic_links(db: AsyncSession) -> int:
    """
    Delete tokens older than 24h. Wire into your Celery beat schedule, or call
    it opportunistically from the request endpoint if you'd rather not add a
    scheduled job yet.
    """
    from sqlalchemy import delete

    cutoff = datetime.utcnow() - timedelta(hours=24)
    result = await db.execute(
        delete(MagicLinkToken).where(MagicLinkToken.created_at < cutoff)
    )
    await db.commit()
    return result.rowcount or 0


# =============================================================================
# WIRING CHECKLIST
# =============================================================================
#
# 1. Move the MagicLinkToken class into app/models/magic_link.py and import it
#    wherever your other models get registered (usually app/models/__init__.py),
#    so Alembic sees it.
#
#        alembic revision --autogenerate -m "Add magic link tokens"   # LOCAL
#        git add alembic/versions/... && git commit && git push
#        # Railway applies it via: alembic upgrade head && uvicorn ...
#
# 2. app/core/config.py — add to Settings:
#
#        RESEND_API_KEY: str = ""
#        MAGIC_LINK_FROM: str = "V-Secrets <noreply@vsecrets.dev>"
#        # FRONTEND_URL already added for billing
#
# 3. app/api/v1/router.py — mount under the SAME prefix as the auth router so
#    the paths come out as /auth/magic-link/*:
#
#        from app.api.v1 import magic_link
#        api_router.include_router(magic_link.router, prefix="/auth", tags=["auth"])
#
# 4. Railway env vars:
#
#        RESEND_API_KEY=re_...
#        MAGIC_LINK_FROM="V-Secrets <noreply@vsecrets.dev>"
#
# 5. Resend: verify vsecrets.dev as a sending domain (SPF + DKIM records) before
#    this works. Unverified domains only deliver to your own address.
#
# =============================================================================
