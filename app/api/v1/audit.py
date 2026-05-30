from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user_only
from app.models.user import User
from app.models.secret import AuditLog

router = APIRouter()


@router.get("")
async def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(get_current_user_only),
    db: AsyncSession = Depends(get_db),
):
    """
    List recent audit logs for the authenticated user.

    Returns recent security-relevant events recorded by V-Secrets.
    """
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
    )

    logs = result.scalars().all()

    return [
        {
            "id": str(log.id),
            "user_id": str(log.user_id) if log.user_id else None,
            "project_id": str(log.project_id) if log.project_id else None,
            "secret_id": str(log.secret_id) if log.secret_id else None,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "api_key_id": str(log.api_key_id) if log.api_key_id else None,
            "request_method": log.request_method,
            "request_path": log.request_path,
            "status_code": log.status_code,
            "event_metadata": log.event_metadata,
            "created_at": log.created_at,
        }
        for log in logs
    ]