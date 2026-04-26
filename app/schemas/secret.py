from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime
from uuid import UUID

class SecretBase(BaseModel):
    key: str = Field(..., min_length=1, max_length=255)
    value: str = Field(..., min_length=1)
    description: Optional[str] = Field(None, max_length=500)
    tags: List[str] = Field(default_factory=list)
    
    @validator('key')
    def validate_key(cls, v):
        # Uppercase and alphanumeric + underscore/dash only
        if not all(c.isalnum() or c in ['_', '-'] for c in v):
            raise ValueError('Key must be alphanumeric with underscores or dashes')
        return v.upper()

class SecretCreate(SecretBase):
    pass

class SecretUpdate(BaseModel):
    value: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None

class SecretResponse(BaseModel):
    id: UUID
    project_id: UUID
    key: str
    description: Optional[str]
    tags: List[str]
    version: int
    created_at: datetime
    updated_at: datetime
    last_accessed_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class SecretWithValue(SecretResponse):
    value: str

class SecretListResponse(BaseModel):
    secrets: List[SecretResponse]
    total: int
    page: int
    page_size: int

class SecretVersionResponse(BaseModel):
    """Response for secret version history."""
    version: int
    created_at: datetime
    created_by: UUID
    
    class Config:
        from_attributes = True