from contextlib import asynccontextmanager

import redis.asyncio as redis
import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.health import router as health_router
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.exceptions import VaultAPIException
from app.middleware.audit import AuditMiddleware

settings = get_settings()


# =========================================================
# Logging
# =========================================================

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        (
            structlog.processors.JSONRenderer()
            if settings.LOG_FORMAT == "json"
            else structlog.dev.ConsoleRenderer()
        ),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


# =========================================================
# Application lifecycle
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "starting_application",
        environment=settings.ENVIRONMENT,
        version=settings.VERSION,
    )

    redis_client = redis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=settings.REDIS_CONNECT_TIMEOUT_SECONDS,
        socket_timeout=settings.REDIS_SOCKET_TIMEOUT_SECONDS,
        health_check_interval=settings.REDIS_HEALTH_CHECK_INTERVAL_SECONDS,
    )

    app.state.redis = redis_client
    app.state.redis_available = False

    try:
        await redis_client.ping()
        app.state.redis_available = True

        logger.info(
            "redis_connected",
            redis_enabled=bool(settings.REDIS_URL),
        )
    except Exception as exc:
        logger.warning(
            "redis_connection_failed_starting_degraded",
            error_type=type(exc).__name__,
            error=str(exc),
        )

    try:
        yield
    finally:
        logger.info("shutting_down_application")

        try:
            await redis_client.aclose()
        except Exception as exc:
            logger.warning(
                "redis_shutdown_failed",
                error_type=type(exc).__name__,
                error=str(exc),
            )


# =========================================================
# FastAPI application
# =========================================================

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    lifespan=lifespan,
)


# =========================================================
# Middleware
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

if settings.AUDIT_LOG_ENABLED:
    app.add_middleware(AuditMiddleware)


# =========================================================
# Routers
# =========================================================

# Ecosystem health.v1 endpoints:
# /api/health
# /api/health/live
# /api/health/ready
#
# Legacy endpoints:
# /health
# /health/deep
# /health/readiness
app.include_router(health_router)

# Business API:
# /api/v1/...
app.include_router(
    api_router,
    prefix=settings.API_V1_PREFIX,
)


# =========================================================
# Exception handlers
# =========================================================

@app.exception_handler(VaultAPIException)
async def vault_exception_handler(
    request: Request,
    exc: VaultAPIException,
) -> JSONResponse:
    logger.error(
        "vault_api_exception",
        error=exc.message,
        status_code=exc.status_code,
        path=request.url.path,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.message,
            "type": exc.__class__.__name__,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    sanitized_errors = []

    for error in exc.errors():
        sanitized_errors.append(
            {
                "type": error.get("type"),
                "loc": error.get("loc"),
                "msg": error.get("msg"),
                "input": error.get("input"),
            }
        )

    logger.warning(
        "request_validation_failed",
        path=request.url.path,
        error_count=len(sanitized_errors),
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation error",
            "details": sanitized_errors,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    logger.exception(
        "unhandled_exception",
        error_type=type(exc).__name__,
        error=str(exc),
        path=request.url.path,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
        },
    )


# =========================================================
# Root
# =========================================================

@app.get(
    "/",
    tags=["Root"],
    include_in_schema=False,
)
async def root() -> dict[str, str]:
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "description": settings.DESCRIPTION,
        "docs": f"{settings.API_V1_PREFIX}/docs",
    }