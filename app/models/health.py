from pydantic import BaseModel, Field
from typing import Literal


class ServiceInfo(BaseModel):
    id: str = Field(..., description="Unique service identifier")
    name: str = Field(..., description="Human readable service name")
    version: str
    environment: str
    stack: str


class HealthCheck(BaseModel):
    name: str
    status: Literal["operational", "degraded"]
    details: str | None = None


class HealthResponse(BaseModel):
    contract_version: Literal["health.v1"] = "health.v1"

    service: ServiceInfo

    status: Literal["operational", "degraded"]

    readiness: Literal[
        "ready",
        "degraded",
    ]

    uptime_seconds: int

    checks: list[HealthCheck]


class LiveResponse(BaseModel):
    status: Literal["alive"] = "alive"


class ReadyResponse(BaseModel):
    status: Literal[
        "ready",
        "not_ready",
    ]