from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from contextlib import asynccontextmanager
import redis.asyncio as redis
import structlog
from sqlalchemy import text

from app.core.config import get_settings
from app.core.exceptions import VaultAPIException
from app.middleware.audit import AuditMiddleware
from app.api.v1.router import api_router

# Ajustar este import al nombre real de tu proyecto
from app.db.session import async_session

settings = get_settings()

# Configure structured logging
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
        structlog.processors.JSONRenderer() if settings.LOG_FORMAT == "json"
        else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.
    """
    logger.info("starting_application", environment=settings.ENVIRONMENT)

    redis_client = redis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=settings.REDIS_CONNECT_TIMEOUT_SECONDS,
        socket_timeout=settings.REDIS_SOCKET_TIMEOUT_SECONDS,
        health_check_interval=settings.REDIS_HEALTH_CHECK_INTERVAL_SECONDS,
    )

    try:
        await redis_client.ping()
        logger.info("redis_connected", redis_enabled=bool(settings.REDIS_URL))
    except Exception as e:
        logger.warning(
            "redis_connection_failed_starting_degraded",
            error_type=type(e).__name__,
            error=str(e),
        )

    app.state.redis = redis_client

    yield

    logger.info("shutting_down_application")
    await redis_client.close()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

if settings.AUDIT_LOG_ENABLED:
    app.add_middleware(AuditMiddleware)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.exception_handler(VaultAPIException)
async def vault_exception_handler(request: Request, exc: VaultAPIException):
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
async def validation_exception_handler(request, exc: RequestValidationError):
    sanitized_errors = []

    for error in exc.errors():
        sanitized_errors.append({
            "type": error.get("type"),
            "loc": error.get("loc"),
            "msg": error.get("msg"),
            "input": error.get("input"),
        })

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation error",
            "details": sanitized_errors,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.exception(
        "unhandled_exception",
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


async def check_database() -> tuple[str, str | None]:
    try:
        async with async_session() as session:
            await session.execute(text("SELECT 1"))
        return "healthy", None
    except Exception as e:
        logger.warning(
            "database_health_check_failed",
            error_type=type(e).__name__,
            error=str(e),
        )
        return "unhealthy", type(e).__name__


async def check_redis(app: FastAPI) -> tuple[str, str | None]:
    try:
        await app.state.redis.ping()
        return "healthy", None
    except Exception as e:
        logger.warning(
            "redis_health_check_failed",
            error_type=type(e).__name__,
            error=str(e),
        )
        return "unhealthy", type(e).__name__


async def build_dependency_health(app: FastAPI) -> dict:
    database_status, database_error = await check_database()
    redis_status, redis_error = await check_redis(app)

    checks = {
        "api": {
            "status": "healthy",
        },
        "database": {
            "status": database_status,
            "error": database_error,
        },
        "redis": {
            "status": redis_status,
            "error": redis_error,
        },
    }

    overall_status = "healthy"

    if database_status != "healthy" or redis_status != "healthy":
        overall_status = "degraded"

    return {
        "status": overall_status,
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "checks": checks,
    }


@app.get("/health")
async def health_check():
    """
    Lightweight liveness check.
    Does not validate external dependencies.
    """
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health/deep")
async def deep_health_check():
    """
    Informational dependency health check.
    Returns 200 even when degraded.
    """
    return await build_dependency_health(app)


@app.get("/health/readiness")
async def readiness_check():
    """
    Strict readiness check.
    Returns 503 if critical dependencies are unavailable.
    """
    result = await build_dependency_health(app)

    if result["status"] != "healthy":
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=result,
        )

    return result


@app.get("/")
async def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "description": settings.DESCRIPTION,
        "docs": f"{settings.API_V1_PREFIX}/docs",
    }