from sqlmodel import SQLModel, Field
from sqlalchemy import String

class UpdateUser(SQLModel):
    
    new_username: str = Field(nullable=False, sa_type=String(64))

class UpdatePassword(SQLModel):
    
    new_password: str = Field(nullable=False, sa_type=String(255))

class GetUser(SQLModel):
    
    username: str = Field(nullable=False, sa_type=String(64))