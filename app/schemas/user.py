from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime
from uuid import UUID


class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=72)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserLimitsResponse(BaseModel):
    projects: Optional[int] = None
    secrets_per_project: Optional[int] = None
    api_keys: Optional[int] = None
    requests_per_minute: Optional[int] = None
    monthly_requests: Optional[int] = None


class UserUsageResponse(BaseModel):
    projects: int = 0
    secrets: int = 0
    api_keys: int = 0


class UserResponse(BaseModel):
    id: UUID
    email: str
    full_name: Optional[str]
    is_active: bool
    is_verified: bool
    plan: str
    created_at: datetime

    # Optional para no romper otros endpoints que usen UserResponse
    limits: Optional[UserLimitsResponse] = None
    usage: Optional[UserUsageResponse] = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"