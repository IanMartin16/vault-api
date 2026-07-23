from fastapi import APIRouter, FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.runtime import get_uptime_seconds
from app.models.health import (
    HealthCheck,
    HealthResponse,
    LiveResponse,
    ReadyResponse,
    ServiceInfo,
)
from app.services.health_service import HealthService

settings = get_settings()

router = APIRouter(tags=["Health"])


# ==========================================================
# Ecosystem health.v1
# ==========================================================

@router.get(
    "/api/health",
    response_model=HealthResponse,
)
async def health(request: Request):

    app: FastAPI = request.app

    dependencies = await HealthService.dependency_checks(app)

    checks = [
        HealthCheck(
            name="database",
            status=dependencies["checks"]["database"]["status"],
            details=dependencies["checks"]["database"]["error"],
        ),
        HealthCheck(
            name="redis",
            status=dependencies["checks"]["redis"]["status"],
            details=dependencies["checks"]["redis"]["error"],
        ),
    ]

    return HealthResponse(
        contract_version="health.v1",
        service=ServiceInfo(
            id="v-secrets",
            name=settings.PROJECT_NAME,
            version=settings.VERSION,
            environment=settings.ENVIRONMENT,
            stack="fastapi",
        ),
        status=dependencies["status"],
        readiness="ready"
        if dependencies["status"] == "operational"
        else "degraded",
        uptime_seconds=get_uptime_seconds(),
        checks=checks,
    )


@router.get(
    "/api/health/live",
    response_model=LiveResponse,
)
async def live():

    return LiveResponse(
        status="alive",
    )


@router.get(
    "/api/health/ready",
    response_model=ReadyResponse,
)
async def readiness(request: Request):

    app: FastAPI = request.app

    ready = await HealthService.is_ready(app)

    if not ready:

        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=ReadyResponse(
                status="not_ready",
            ).model_dump(),
        )

    return ReadyResponse(
        status="ready",
    )


# ==========================================================
# Legacy endpoints
# ==========================================================

@router.get("/health")
async def legacy_health():

    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/health/deep")
async def legacy_deep(request: Request):

    app: FastAPI = request.app

    return await HealthService.dependency_checks(app)


@router.get("/health/readiness")
async def legacy_readiness(request: Request):

    app: FastAPI = request.app

    ready = await HealthService.is_ready(app)

    if not ready:

        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=await HealthService.dependency_checks(app),
        )

    return await HealthService.dependency_checks(app)