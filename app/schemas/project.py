from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from uuid import UUID

class ProjectBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    environment: str = Field(default="production")
    color: str = Field(default="#3B82F6", pattern="^#[0-9A-Fa-f]{6}$")  # ← CAMBIO: regex → pattern

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    environment: Optional[str] = None
    color: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")  # ← CAMBIO: regex → pattern

class ProjectResponse(BaseModel):
    id: UUID
    owner_id: UUID
    name: str
    description: Optional[str]
    environment: str
    color: str
    created_at: datetime
    updated_at: datetime
    secret_count: int = 0
    
    class Config:
        from_attributes = True