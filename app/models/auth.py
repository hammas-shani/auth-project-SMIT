from pydantic import BaseModel , Field

from typing import Optional


class usersignup(BaseModel):
    email: str = Field(..., pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    password: str = Field(..., min_length=8, max_length=100)
    name: Optional[str] = Field(None, max_length=100)   

class userlogin(BaseModel):
    email: str = Field(..., pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
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

    class Config:
        orm_mode = True 
