"""
Pydantic schemas for API Key operations.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import datetime
from uuid import UUID

ALLOWED_API_KEY_SCOPES = {
    "projects:read",
    "projects:write",
    "secrets:read",
    "secrets:reveal",
    "secrets:write",
    "secrets:delete",
    "api_keys:write",
}


class APIKeyCreate(BaseModel):
    """Schema for creating a new API key."""
    name: str = Field(..., min_length=1, max_length=100, description="Descriptive name for the API key")
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650, description="Days until expiration (1-3650, None = never)")
    project_id: Optional[UUID] = Field(None, description="Optional project scope (None = global access)")
    scopes: List[str] = Field(default_factory=lambda: [
        "projects:read",
        "secrets:read",
        "secrets:reveal",
    ])

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, scopes: List[str]) -> List[str]:
        if not scopes:
            raise ValueError("At least one scope is required")

        normalized = []
        for scope in scopes:
            clean_scope = scope.strip()
            if clean_scope not in ALLOWED_API_KEY_SCOPES:
                raise ValueError(f"Invalid scope: {clean_scope}")
            normalized.append(clean_scope)

        return sorted(set(normalized))

class APIKeyResponse(BaseModel):
    """Schema for API key response (without raw key)."""
    id: UUID
    name: str
    key_prefix: str  # First 12 chars: "vault_abc12"
    project_id: Optional[UUID]
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class APIKeyWithSecret(APIKeyResponse):
    """
    Schema for API key response WITH raw key.
    
    Only used during creation - raw key is shown once.
    """
    api_key: str = Field(..., description="Full API key (shown only once during creation)")