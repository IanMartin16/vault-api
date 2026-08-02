# =============================================================================
# ADD TO YOUR FastAPI BACKEND
# File: app/api/v1/billing.py  (new file)
# =============================================================================
#
# Stripe Checkout integration, hosted flow.
#
# Design decisions and why:
#
#   1. HOSTED CHECKOUT, not Elements. Stripe hosts the payment page, so card
#      data never touches your servers and PCI scope stays minimal. Elements is
#      for when you need UI control you can't get otherwise — you don't.
#
#   2. WEBHOOK-FIRST PROVISIONING. The plan is upgraded when the webhook fires,
#      never when the browser hits the success URL. A user who closes the tab
#      mid-redirect still gets provisioned; a user who forges a success URL
#      does not.
#
#   3. PINNED API VERSION. Stripe evolves. Without a pin, a change on their
#      side can break production silently. Verify the version below against
#      your Stripe dashboard before going live.
#
#   4. IDEMPOTENT HANDLERS. Stripe retries webhooks. Every handler here sets
#      fields to a computed value rather than incrementing or appending, so a
#      replay is harmless.
#
# =============================================================================

from typing import Optional

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.api.deps import get_current_user_only, get_db
from app.core.config import get_settings
from app.models.user import User

settings = get_settings()
logger = structlog.get_logger()

stripe.api_key = settings.STRIPE_SECRET_KEY
# Pin the API version — verify this matches your Stripe dashboard setting.
stripe.api_version = "2026-06-24.dahlia"

router = APIRouter()


# -----------------------------------------------------------------------------
# Plan catalogue
# -----------------------------------------------------------------------------
# Price IDs live in env vars, never in code — they differ between test and live
# mode, and hardcoding them guarantees a production incident.

PLANS = {
    "pro": {
        "price_id": settings.STRIPE_PRICE_PRO,
        "limits": {"projects": 10, "secrets_per_project": 500, "api_keys": 20},
    },
    "business": {
        "price_id": settings.STRIPE_PRICE_BUSINESS,
        "limits": {"projects": None, "secrets_per_project": 10000, "api_keys": None},
    },
}

# Reverse lookup: Stripe price ID -> plan name. Used by the webhook to figure
# out which plan a subscription corresponds to.
PRICE_TO_PLAN = {
    config["price_id"]: name for name, config in PLANS.items() if config["price_id"]
}


# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------

class CheckoutRequest(BaseModel):
    plan: str  # "pro" | "business"


class CheckoutResponse(BaseModel):
    url: str


class PortalResponse(BaseModel):
    url: str


class SubscriptionStatus(BaseModel):
    plan: str
    status: Optional[str] = None
    cancel_at_period_end: bool = False
    current_period_end: Optional[int] = None
    has_subscription: bool = False


# -----------------------------------------------------------------------------
# Create a Checkout Session
# -----------------------------------------------------------------------------

@router.post("/checkout-session", response_model=CheckoutResponse)
async def create_checkout_session(
    payload: CheckoutRequest,
    current_user: User = Depends(get_current_user_only),
    db: AsyncSession = Depends(get_db),
):
    """Start a subscription. Returns a Stripe-hosted URL to redirect the user to."""
    if not settings.STRIPE_SECRET_KEY:
        logger.error("stripe_not_configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing is not configured on this server.",
        )

    plan_config = PLANS.get(payload.plan)
    if not plan_config or not plan_config["price_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown or unconfigured plan: {payload.plan}",
        )

    customer_id = getattr(current_user, "stripe_customer_id", None)

    # Every Stripe call is wrapped: a provider failure should surface as a
    # readable error, not an unhandled 500 that loses its CORS headers.
    try:
        if not customer_id:
            customer = stripe.Customer.create(
                email=current_user.email,
                name=current_user.full_name or None,
                metadata={"user_id": str(current_user.id)},
            )
            customer_id = customer.id
            current_user.stripe_customer_id = customer_id
            await db.commit()

        session = stripe.checkout.Session.create(
            mode="subscription",
            customer=customer_id,
            line_items=[{"price": plan_config["price_id"], "quantity": 1}],
            success_url=f"{settings.FRONTEND_URL}/settings/billing?checkout=success",
            cancel_url=f"{settings.FRONTEND_URL}/settings/billing?checkout=cancelled",
            metadata={"user_id": str(current_user.id), "plan": payload.plan},
            subscription_data={
                "metadata": {"user_id": str(current_user.id), "plan": payload.plan},
            },
            allow_promotion_codes=True,
            billing_address_collection="auto",
        )
    except stripe.StripeError as exc:
        logger.error(
            "stripe_checkout_failed",
            user_id=str(current_user.id),
            plan=payload.plan,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Stripe error: {exc.user_message or str(exc)}",
        )

    logger.info(
        "checkout_session_created",
        user_id=str(current_user.id),
        plan=payload.plan,
        session_id=session.id,
    )

    return CheckoutResponse(url=session.url)


# -----------------------------------------------------------------------------
# Customer Portal — self-service plan changes and cancellation
# -----------------------------------------------------------------------------

@router.post("/portal-session", response_model=PortalResponse)
async def create_portal_session(
    current_user: User = Depends(get_current_user_only),
):
    """Open Stripe's hosted billing portal."""
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing is not configured on this server.",
        )

    customer_id = getattr(current_user, "stripe_customer_id", None)
    if not customer_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No billing account yet. Subscribe to a plan first.",
        )

    try:
        session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=f"{settings.FRONTEND_URL}/settings/billing",
        )
    except stripe.StripeError as exc:
        logger.error("stripe_portal_failed", user_id=str(current_user.id), error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Stripe error: {exc.user_message or str(exc)}",
        )

    return PortalResponse(url=session.url)


# -----------------------------------------------------------------------------
# Current subscription state (for the billing page)
# -----------------------------------------------------------------------------

@router.get("/subscription", response_model=SubscriptionStatus)
async def get_subscription(
    current_user: User = Depends(get_current_user_only),
):
    """Read the live subscription from Stripe rather than trusting local state."""
    subscription_id = getattr(current_user, "stripe_subscription_id", None)

    if not subscription_id:
        return SubscriptionStatus(
            plan=current_user.plan or "free",
            has_subscription=False,
        )

    try:
        subscription = stripe.Subscription.retrieve(subscription_id)
    except stripe.StripeError as exc:
        logger.warning(
            "subscription_fetch_failed",
            user_id=str(current_user.id),
            error=str(exc),
        )
        return SubscriptionStatus(
            plan=current_user.plan or "free",
            has_subscription=False,
        )

    return SubscriptionStatus(
        plan=current_user.plan or "free",
        status=subscription.status,
        cancel_at_period_end=bool(subscription.cancel_at_period_end),
        current_period_end=subscription.current_period_end,
        has_subscription=True,
    )


# -----------------------------------------------------------------------------
# Webhook
# -----------------------------------------------------------------------------
#
# MOUNTING NOTE: this route must NOT sit behind auth, and signature verification
# needs the RAW request body. If any middleware reads or rewrites the body
# before this handler runs, verification will fail. Check your AuditMiddleware —
# if it touches request bodies, exclude this path.

@router.post("/webhook", status_code=status.HTTP_200_OK)
async def stripe_webhook(
    request: Request,
    stripe_signature: Optional[str] = Header(None, alias="Stripe-Signature"),
    db: AsyncSession = Depends(get_db),
):
    """Receive subscription lifecycle events from Stripe."""
    raw_body = await request.body()

    if not settings.STRIPE_WEBHOOK_SECRET:
        logger.error("stripe_webhook_secret_missing")
        raise HTTPException(status_code=500, detail="Webhook not configured")

    # Signature verification is what makes this endpoint safe to expose. Without
    # it, anyone who knows the URL could grant themselves a Business plan.
    try:
        event = stripe.Webhook.construct_event(
            payload=raw_body,
            sig_header=stripe_signature,
            secret=settings.STRIPE_WEBHOOK_SECRET,
        )
    except ValueError:
        logger.warning("stripe_webhook_bad_payload")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.SignatureVerificationError:
        logger.warning("stripe_webhook_bad_signature")
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]

    # construct_event returns StripeObject, which doesn't expose dict.get() in
    # this SDK version. Convert once here so every handler works with a plain
    # dict instead of guarding each field access.
    raw_object = event["data"]["object"]
    data = (
        raw_object.to_dict_recursive()
        if hasattr(raw_object, "to_dict_recursive")
        else dict(raw_object)
    )

    logger.info("stripe_webhook_received", event_type=event_type, event_id=event["id"])

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(data, db)

    elif event_type in ("customer.subscription.updated", "customer.subscription.created"):
        await _handle_subscription_changed(data, db)

    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(data, db)

    elif event_type == "invoice.payment_failed":
        await _handle_payment_failed(data, db)

    # Always 200 for events we don't handle — a non-200 makes Stripe retry
    # forever on events we intentionally ignore.
    return {"received": True}


# -----------------------------------------------------------------------------
# Webhook handlers
# -----------------------------------------------------------------------------

async def _get_user_by_customer(
    customer_id: str, db: AsyncSession
) -> Optional[User]:
    stmt = select(User).where(User.stripe_customer_id == customer_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _handle_checkout_completed(session: dict, db: AsyncSession):
    """First successful payment — link the subscription and set the plan."""
    user_id = (session.get("metadata") or {}).get("user_id")
    plan = (session.get("metadata") or {}).get("plan")
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")

    if not user_id:
        logger.warning("checkout_completed_no_user_id", customer=customer_id)
        return

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        logger.warning("checkout_completed_user_not_found", user_id=user_id)
        return

    user.stripe_customer_id = customer_id
    user.stripe_subscription_id = subscription_id
    user.subscription_status = "active"
    if plan:
        user.plan = plan

    await db.commit()

    logger.info(
        "subscription_activated",
        user_id=str(user.id),
        plan=plan,
        subscription_id=subscription_id,
    )


async def _handle_subscription_changed(subscription: dict, db: AsyncSession):
    """
    Plan switch, renewal, or status change (active, past_due, unpaid...).

    The plan is derived from the price ID on the subscription rather than from
    metadata, because a plan change made in the Customer Portal updates the
    price but not the original metadata.
    """
    customer_id = subscription.get("customer")
    user = await _get_user_by_customer(customer_id, db)

    if not user:
        logger.warning("subscription_changed_user_not_found", customer=customer_id)
        return

    items = (subscription.get("items") or {}).get("data") or []
    price_id = items[0]["price"]["id"] if items else None
    plan = PRICE_TO_PLAN.get(price_id)

    user.stripe_subscription_id = subscription.get("id")
    user.subscription_status = subscription.get("status")

    # Only downgrade the plan when the subscription is genuinely inactive.
    # A past_due subscription keeps access while Stripe retries the payment.
    if subscription.get("status") in ("active", "trialing") and plan:
        user.plan = plan
    elif subscription.get("status") in ("canceled", "incomplete_expired"):
        user.plan = "free"

    await db.commit()

    logger.info(
        "subscription_updated",
        user_id=str(user.id),
        plan=user.plan,
        status=user.subscription_status,
    )


async def _handle_subscription_deleted(subscription: dict, db: AsyncSession):
    """Subscription ended — drop to free."""
    customer_id = subscription.get("customer")
    user = await _get_user_by_customer(customer_id, db)

    if not user:
        return

    user.plan = "free"
    user.subscription_status = "canceled"
    user.stripe_subscription_id = None

    await db.commit()

    logger.info("subscription_canceled", user_id=str(user.id))


async def _handle_payment_failed(invoice: dict, db: AsyncSession):
    """
    Payment failed. Don't revoke access here — Stripe Smart Retries will attempt
    the charge again over the following days, and most failures recover. The
    subscription.updated event handles the final downgrade if they never do.
    """
    customer_id = invoice.get("customer")
    user = await _get_user_by_customer(customer_id, db)

    if not user:
        return

    user.subscription_status = "past_due"
    await db.commit()

    logger.warning(
        "payment_failed",
        user_id=str(user.id),
        invoice_id=invoice.get("id"),
        attempt=invoice.get("attempt_count"),
    )


# =============================================================================
# WIRING CHECKLIST
# =============================================================================
#
# 1. requirements.txt:
#        stripe>=11.0.0
#
# 2. app/models/user.py — add these columns:
#
#        stripe_customer_id = Column(String, nullable=True, index=True)
#        stripe_subscription_id = Column(String, nullable=True)
#        subscription_status = Column(String, nullable=True)
#
#    Then: alembic revision --autogenerate -m "Add Stripe billing fields"
#          alembic upgrade head
#
# 3. app/core/config.py — add to Settings:
#
#        STRIPE_SECRET_KEY: str = ""
#        STRIPE_WEBHOOK_SECRET: str = ""
#        STRIPE_PRICE_PRO: str = ""
#        STRIPE_PRICE_BUSINESS: str = ""
#        FRONTEND_URL: str = "https://vsecrets.dev"
#
# 4. app/api/v1/router.py:
#
#        from app.api.v1 import billing
#        api_router.include_router(billing.router, prefix="/billing", tags=["billing"])
#
# 5. Verify no middleware consumes the request body before /billing/webhook.
#    Signature verification needs the raw bytes.
#
# =============================================================================
