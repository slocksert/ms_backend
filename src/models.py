from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime, timezone
from sqlalchemy import String, Boolean
import uuid

class Users(SQLModel, table=True):

    __tablename__ = "users"

    id:Optional[int] = Field(default=None, primary_key=True)
    uuid:str = Field(default=uuid.uuid4(), unique=True)
    username:str = Field(nullable=False, unique=True, sa_type=String(20))
    password:str = Field(nullable=False, sa_type=String(255))
    email:str = Field(nullable=False, unique=True, sa_type=String(30))
    company_name:str = Field(sa_type=String(64))
    phone:str = Field(sa_type=String(11), nullable=True, default=None)
    cnpj:str = Field(nullable=True, unique=True, default=None)
    adress:str = Field(nullable=False, sa_type=String(60))
    city:str = Field(nullable=False, sa_type=String(32))
    state:str = Field(nullable=False, sa_type=String(32))
    cep:str = Field(nullable=False, sa_type=String(8)) 
    district:str = Field(nullable=False, sa_type=String(25))
    complement:str = Field(nullable=True, sa_type=String(60))
    image_uuid:str = Field(nullable=True, default="Sem imagem")
    is_active:bool = Field(default=True, nullable=False)
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    role_id: int = Field(default=2 ,foreign_key='roles.id', nullable=False)

class Roles(SQLModel, table=True):

    __tablename__ = "roles"

    id:Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(nullable=False)