import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool
import os

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
            "username":"0000", 
            "email":"0000@gmail.com",
            "company_name":"0000",
            "has_cnpj":0,
            "password":"00000000000"
        }
    )
    
    app.dependency_overrides.clear()

    assert response.status_code == 201

def test_login(client, session):
    dependecy(session)

    response = client.post(
        "/user/login",
        data={
            "username":"0000",
            "password":"00000000000"
        }
    )

    assert response.status_code == 200

    
def test_delete_tables():
    SQLModel.metadata.drop_all(engine, checkfirst=True)
    app.dependency_overrides.clear()

def test_delete_db():
    os.remove("test.db")
    assert not os.path.exists("test.db")

