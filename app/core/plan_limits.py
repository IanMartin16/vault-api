from app.core.config import get_settings

settings = get_settings()

def normalize_plan(plan) -> str:
    """
    Accepts enum or string plan values.
    """
    if hasattr(plan, "value"):
        return plan.value
    return str(plan)

def get_plan_limits(plan: str) -> dict:
    plan_name = normalize_plan(plan)
    """
    Return limits for a subscription plan.
    Enterprise uses None for unlimited limits.
    """
    limits = {
        "free": {
            "projects": settings.MAX_PROJECTS_FREE,
            "secrets_per_project": settings.MAX_SECRETS_FREE,
            "api_keys": settings.MAX_API_KEYS_FREE,
            "requests_per_minute": settings.RATE_LIMIT_REQUESTS,
            "monthly_requests": settings.RATE_LIMIT_FREE,
        },
        "starter": {
            "projects": getattr(settings, "MAX_PROJECTS_STARTER", 10),
            "secrets_per_project": getattr(settings, "MAX_SECRETS_STARTER", 200),
            "api_keys": getattr(settings, "MAX_API_KEYS_STARTER", 10),
            "requests_per_minute": 300,
            "monthly_requests": settings.RATE_LIMIT_STARTER,
        },
        "pro": {
            "projects": getattr(settings, "MAX_PROJECTS_PRO", 50),
            "secrets_per_project": getattr(settings, "MAX_SECRETS_PRO", 1000),
            "api_keys": getattr(settings, "MAX_API_KEYS_PRO", 50),
            "requests_per_minute": 1000,
            "monthly_requests": settings.RATE_LIMIT_PRO,
        },
        "enterprise": {
            "projects": None,
            "secrets_per_project": None,
            "api_keys": None,
            "requests_per_minute": 5000,
            "monthly_requests": settings.RATE_LIMIT_ENTERPRISE,
        },
    }

    return limits.get(plan_name, limits["free"])