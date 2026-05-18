from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class UserSignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    name: Optional[str] = Field(None, max_length=100)


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class TokenRefreshRequest(BaseModel):
    refresh_token: str

class UserRegistrationResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    is_superuser: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TokenExchangeResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class StandardActionResponse(BaseModel):
    detail: str


class UserProfileResponse(BaseModel):
    id: int
    email: str
    name: Optional[str]
    is_active: bool
    is_superuser: bool

    class Config:
        from_attributes = True
