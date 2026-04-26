from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime
from uuid import UUID

class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=72)  # ← Agregar max_length

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: UUID
    email: str
    full_name: Optional[str]
    is_active: bool
    is_verified: bool
    plan: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    project_id: Optional[UUID] = None
    expires_in_days: Optional[int] = None

class APIKeyResponse(BaseModel):
    id: UUID
    name: str
    key_prefix: str
    project_id: Optional[UUID]
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class APIKeyWithSecret(APIKeyResponse):
    api_key: str  # Only shown once on creation
