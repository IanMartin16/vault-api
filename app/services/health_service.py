from __future__ import annotations

from fastapi import FastAPI
from sqlalchemy import text
import structlog

from app.core.config import get_settings
from app.db.session import async_session

settings = get_settings()
logger = structlog.get_logger()


class HealthService:
    """
    Builds ecosystem health responses.

    - Lightweight checks
    - No business logic
    - No encryption
    - No secrets access
    """

    @staticmethod
    async def check_database() -> tuple[str, str | None]:
        try:
            async with async_session() as session:
                await session.execute(text("SELECT 1"))

            return "operational", None

        except Exception as exc:
            logger.warning(
                "database_health_check_failed",
                error_type=type(exc).__name__,
                error=str(exc),
            )

            return "degraded", type(exc).__name__

    @staticmethod
    async def check_redis(app: FastAPI) -> tuple[str, str |None]:
        try:
            await app.state.redis.ping()

            return "operational", None

        except Exception as exc:
            logger.warning(
                "redis_health_check_failed",
                error_type=type(exc).__name__,
                error=str(exc),
            )

            return "degraded", type(exc).__name__

    @classmethod
    async def dependency_checks(
        cls,
        app: FastAPI,
    ) -> dict:

        db_status, db_error = await cls.check_database()
        redis_status, redis_error = await cls.check_redis(app)

        overall = "operational"

        if (
            db_status != "operational"
            or redis_status != "operational"
        ):
            overall = "degraded"

        return {
            "status": overall,
            "checks": {
                "database": {
                    "status": db_status,
                    "error": db_error,
                },
                "redis": {
                    "status": redis_status,
                    "error": redis_error,
                },
            },
        }

    @classmethod
    async def is_ready(cls, app: FastAPI) -> bool:

        result = await cls.dependency_checks(app)

        return result["status"] == "operational"