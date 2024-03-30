import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool
import os
from decouple import config

from main import app
from database import get_session
from repository import create_roles, create_admin

engine = create_engine(
    'sqlite:///test.db',
    connect_args={'check_same_thread':False},
    poolclass=StaticPool
)

@pytest.fixture(name="session")
def session_fixture():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

@pytest.fixture()
def client():
    return TestClient(app)

def dependecy(session):
    def get_session_override():
        return session
    
    app.dependency_overrides[get_session] = get_session_override

def create_table(session):
    SQLModel.metadata.create_all(engine, checkfirst=True)
    create_roles(session)
    create_admin(session)

def test_create_user(client, session):
    dependecy(session)
    create_table(session)

    response =  client.post(
        "/user/register",
        headers={'User-Agent':'application/json'},
        json={
            "username":"admin", 
            "email":"admin@admin.com",
            "company_name":"Maceió Segura",
            "has_cnpj":0,
            "password":config("ADMIN_PWD")
        }
    )
    
    assert response.status_code == 409

def test_login(client, session):
    dependecy(session)

    response = client.post(
        "/user/login",
        data={
            "username":"admin",
            "password":config("ADMIN_PWD")
        }
    )

    assert response.status_code == 200

    
def test_delete_tables():
    SQLModel.metadata.drop_all(engine, checkfirst=True)
    app.dependency_overrides.clear()

def test_delete_db():
    os.remove("test.db")
    assert not os.path.exists("test.db")

