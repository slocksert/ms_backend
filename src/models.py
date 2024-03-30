from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime, timezone
from sqlalchemy import String, Boolean

class Users(SQLModel, table=True):

    __tablename__ = "users"

    id:Optional[int] = Field(default=None, primary_key=True)
    username:str = Field(nullable=False, unique=True, sa_type=String(20))
    password:str = Field(nullable=False, sa_type=String(255))
    email:str = Field(nullable=False, unique=True, sa_type=String(64))
    company_name:str = Field(sa_type=String(64))
    phone:str = Field(sa_type=String(11), nullable=True, default=None)
    has_cnpj:bool = Field(nullable=False, unique=False, sa_type=Boolean(create_constraint=True), default=False)
    cnpj:str = Field(nullable=True, unique=True, default=None)
    image_uuid:str = Field(nullable=True, default="Sem imagem")
    is_active:bool = Field(default=True, nullable=False)
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    role_id: int = Field(default=2 ,foreign_key='roles.id', nullable=False)

class UserUpdate(SQLModel):
    new_username:str = Field(nullable=False, sa_type=String(20))

class Roles(SQLModel, table=True):

    __tablename__ = "roles"

    id:Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(nullable=False)