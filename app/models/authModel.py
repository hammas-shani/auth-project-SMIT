from pydantic import BaseModel, ConfigDict, Field

from typing import Optional


_EMAIL_PATTERN = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"


class usersignup(BaseModel):
    email: str = Field(..., pattern=_EMAIL_PATTERN)
    password: str = Field(..., min_length=8, max_length=100)
    name: Optional[str] = Field(None, max_length=100)


class userlogin(BaseModel):
    email: str = Field(..., pattern=_EMAIL_PATTERN)
    password: str = Field(..., min_length=8, max_length=100)


class token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class token_data(BaseModel):
    email: Optional[str] = None


class user(BaseModel):
    id: int
    email: str
    name: Optional[str] = None


model_config = ConfigDict(from_attributes=True)
