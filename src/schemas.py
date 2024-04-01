from pydantic import BaseModel
from sqlmodel import Field
from sqlalchemy import String, Boolean

class UpdateUser(BaseModel):
    
    new_username: str = Field(nullable=False, sa_type=String(64))

class UpdatePassword(BaseModel):
    
    old_password: str = Field(nullable=False, sa_type=String(255))
    new_password: str = Field(nullable=False, sa_type=String(255))

class GetUser(BaseModel):
    
    username: str = Field(nullable=False, sa_type=String(64))

class UpdateStatus(BaseModel):

    username: str = Field(nullable=False, sa_type=String(64))
    status: bool = Field(nullable=False)