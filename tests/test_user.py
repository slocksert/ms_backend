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

def test_create_table(session):
    dependecy(session)
    SQLModel.metadata.create_all(engine, checkfirst=True)
    create_roles(session)
    create_admin(session)
    assert os.path.exists("test.db")

def login(client, email:str = "0000@gmail.com", password:str = "test123456"):
    response = client.post(
        "/user/login",
        data={
            "username":email,
            "password":password
        }
    )
    return response

def test_create_user(client):
    response =  client.post(
        "/user/register",
        headers={'User-Agent':'application/json'},
        json={
            "name":"test", 
            "email":"0000@gmail.com",
            "password":"test123456",
        }
    )
    assert response.status_code == 201

def test_login(client):
    response = login(client)
    assert response.status_code == 200

def test_home_unauthorized(client):
    response = client.get("/user")
    assert response.status_code == 401

def test_home_authorized(client):
    response = login(client)
    response = client.get(
        "/user",
        headers={
            "Authorization":f"Bearer {response.cookies.get('jwt')}"
        }
    )
    assert response.status_code == 200

def test_get_image(client):
    response = login(client)
    response = client.get(
        '/user/getimage',
        headers={
            "Authorization":f"Bearer {response.cookies.get('jwt')}"
        }
    )
    assert response.json()['image_uuid'] == "NoImage"

def test_send_image(client):
    response = login(client)

    with open("storage/pictures/NoImage.png", "rb") as image_file:
        response = client.post(
            '/user/sendimage',
            files={"file": ("NoImage.png", image_file, "image/jpeg")},
            headers={
                "Authorization": f"Bearer {response.cookies.get('jwt')}"
            }
        )
    assert response.status_code == 201

def test_delete_image(client):
    image_login = login(client)
    image_request = client.get(
        "/user/getimage",
        headers={
            "Authorization":f"Bearer {image_login.cookies.get('jwt')}"
        }

    )
    image_name = image_request.json()['image_uuid']
    
    try:
        os.remove(f'storage/pictures/{image_name}')
    except FileNotFoundError:
        ...

    assert not os.path.exists(f"storage/pictures/{image_name}")

def test_send_contact_form(client):
    response = login(client)
    response = client.post(
        "/user/contact",
        headers={
            "Authorization":f"Bearer {response.cookies.get('jwt')}"
        },
        json={
            "company_name": "string",
            "phone": "string",
            "cnpj": "12345678901234",
            "adress": "string",
            "city": "string",
            "state": "string",
            "cep": "string",
            "district": "string",
            "complement": "string",
            "description": "string"
        }
    )

    assert response.status_code == 200

def test_update_password(client):
    response = login(client)
    response = client.put(
        "/user/updatepwd",
        headers={
            "Authorization":f"Bearer {response.cookies.get('jwt')}"
        },
        json={
            "new_password":"testingpassword",
            "old_password":"test123456"
        }
    )
    assert response.status_code == 200

def test_update_user(client):
    response = login(client, password="testingpassword")
    response = client.put(
        "/user/updateuser",
        headers={
            "Authorization":f"Bearer {response.cookies.get('jwt')}"
        },
        json={
            "new_username":"test_update_user"
        }
    )

    assert response.status_code == 200

##Admin tests

def login_adm(client, email:str = "admin@admin.com", password:str = "adminadmin"):
    response = client.post(
        "/user/login",
        data={
            "username":email,
            "password":password
        }
    )
    return response

def test_create_user_adm(client):
    response =  client.post(
        "/user/register",
        headers={'User-Agent':'application/json'},
        json={
            "username":"admin", 
            "email":"admin@admin.com",
            "password":"adminadmin",
        }
    )
    assert response.status_code == 409

def test_login_adm(client):
    response = login_adm(client)
    assert response.status_code == 200

def test_home_unauthorized_adm(client):
    response = client.get("/user/adm")
    assert response.status_code == 401

def test_home_authorized_adm(client):
    response = login_adm(client)
    response = client.get(
        "/user/adm",
        headers={
            "Authorization":f"Bearer {response.cookies.get('jwt')}"
        }
    )
    assert response.status_code == 200

def test_get_users(client):
    response = login_adm(client)
    response = client.get(
        "/user/adm/getusers",
        headers={"Authorization":f"Bearer {response.cookies.get('jwt')}"}
    )
    assert response.status_code == 200

def test_get_user(client):
    response = login_adm(client)
    jwt_token = response.cookies.get('jwt')

    response = client.get(
        "/user/adm/getusers?username=admin",
        headers={"Authorization": f"Bearer {jwt_token}"}
    )
    assert response.status_code == 200

def test_update_status(client):
    response = login_adm(client)
    response = client.post(
        "/user/adm/updatestatus",
        headers={"Authorization":f"Bearer {response.cookies.get('jwt')}"},
        json={
            "username":"admin",
            "status":False
        }
    )

def test_delete_user(client):
    response = login_adm(client)
    jwt_token = response.cookies.get('jwt')

    response = client.post(
        "/user/adm/deleteuser",
        headers={"Authorization": f"Bearer {jwt_token}"},
        json={"username": "admin"}
    )
    assert response.status_code == 200

    
def test_delete_tables():
    SQLModel.metadata.drop_all(engine, checkfirst=True)
    app.dependency_overrides.clear()

def test_delete_db():
    os.remove("test.db")
    assert not os.path.exists("test.db")