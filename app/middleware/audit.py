from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from datetime import datetime
import structlog

from app.db.session import async_session
from app.models.secret import AuditLog

logger = structlog.get_logger()


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log all API operations for audit trail.
    Captures request/response details and stores in database.
    """

    async def dispatch(self, request: Request, call_next):
        # Skip audit for health checks and docs
        if request.url.path in ["/health", "/", "/openapi.json"] or "/docs" in request.url.path:
            return await call_next(request)

        start_time = datetime.utcnow()

        # Process request first so dependencies can populate request.state
        response: Response = await call_next(request)

        # Extract auth info after endpoint/dependencies ran
        user_id = getattr(request.state, "user_id", None)
        api_key_id = getattr(request.state, "api_key_id", None)
        auth_method = getattr(request.state, "auth_method", None)

        # Calculate duration
        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

        logger.info(
            "api_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            user_id=str(user_id) if user_id else None,
            api_key_id=str(api_key_id) if api_key_id else None,
            auth_method=auth_method,
            ip=request.client.host if request.client else None,
        )

        try:
            async with async_session() as db:
                audit_log = AuditLog(
                    user_id=user_id,
                    api_key_id=api_key_id,
                    action=request.method,
                    resource_type=self._extract_resource_type(request.url.path),
                    request_method=request.method,
                    request_path=request.url.path,
                    status_code=response.status_code,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent", "")[:500],
                    event_metadata={
                        "duration_ms": duration_ms,
                        "auth_method": auth_method,
                    },
                )
                db.add(audit_log)
                await db.commit()
        except Exception as e:
            logger.error("audit_log_failed", error=str(e))

        return response

    def _extract_resource_type(self, path: str) -> str:
        """Extract resource type from URL path."""
        if "/secrets" in path:
            return "secret"
        elif "/projects" in path:
            return "project"
        elif "/api-keys" in path:
            return "api_key"
        elif "/users" in path:
            return "user"
        elif "/audit-logs" in path:
            return "audit"
        return "unknown"