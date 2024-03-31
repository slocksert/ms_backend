from fastapi import status, APIRouter, Depends, Response, Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

import uuid
from sqlmodel import Session

import models
from repository import AuthUser
from depends import token_verifier_home, verify_adm
from database import get_session

register = APIRouter(prefix='/user')
login = APIRouter(prefix='/user')
index = APIRouter(dependencies=[Depends(token_verifier_home)])
adm_route = APIRouter(dependencies=[Depends(verify_adm)])
au = AuthUser()

@register.post('/register')
async def create_user(user: models.Users,session: Session = Depends(get_session)):
    au.user_register(user=user, session=session)
    
    return JSONResponse(
        content=({
            "msg": "User created succesfully"
        }), status_code=status.HTTP_201_CREATED
    )

@login.post('/login')
async def user_login(response: Response, 
                     request_form_user: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):

    user = models.Users(
        username=request_form_user.username,
        password=request_form_user.password
    )

    data = au.user_login(user=user, session=session)

    response = JSONResponse(content={
        'access_token':data['access_token'],
        'exp': data['exp']
    },
        status_code=status.HTTP_200_OK)

    response.set_cookie(key="jwt", value=data['access_token'])
    return response

@index.get('/user')
async def home():
    return JSONResponse(
        content={"message":"Authorized"},  
        status_code=status.HTTP_200_OK
    )

@index.post('/user/sendimage')
async def send_image(request: Request, response = Response, session: Session = Depends(get_session)):
    try:
        image_bytes = await request.body()
        filename = f"{uuid.uuid4()}.jpg"
        
        au.write_image(filename=filename, image_bytes=image_bytes)

    except Exception as e:
        return JSONResponse(
            content={"error": str(e)},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    
    cookie = request.cookies.get("jwt")
    
    response = JSONResponse(
        content={
            "filename":filename,
            "cookie": cookie
        }, status_code=status.HTTP_201_CREATED
    )

    au.send_uuid_image_to_db(filename, cookie, session)

    return response

@index.put('/user/updateuser/{new_username}')
async def update_user(request:Request, response:Response, new_username:str, session: Session = Depends(get_session)):
    cookie = request.cookies.get('jwt')
    uuid = au.decode_jwt_and_verify(cookie, session)

    data = {
        "uuid": uuid, 
        "new_username": new_username
    }

    au.update_username(data=data, session=session)

    response = JSONResponse(
        content={"message":"Username updated successfully."},
        status_code=status.HTTP_200_OK)

    return response

@index.put('/user/updatepwd/{old_password}&&{new_password}')
async def update_password(old_password:str ,new_password:str, session:Session = Depends(get_session)):
    ...

@adm_route.delete('/user/adm/deleteuser/{username}')
async def delete_user(username, session:Session = Depends(get_session)):
    au.delete_user(username, session)

    return JSONResponse(
        content={f"User {username} deleted successfully."},
        status_code=status.HTTP_200_OK
    )

@adm_route.get('/user/adm')
async def adm():
    return JSONResponse(
        content={"message":"Authorized"},  
        status_code=status.HTTP_200_OK
    )

@adm_route.get('/user/adm/getusers')
async def get_all_users(session: Session = Depends(get_session)): 
    users = au.get_users(session)

    response = JSONResponse(
        content=users,
        status_code=status.HTTP_200_OK
    )
    return response

@adm_route.get('/user/adm/getuser/{username}')
async def get_user_by_username(username, session: Session = Depends(get_session)):
    user = au.get_user_by_username(username, session)

    response = JSONResponse(
        content=user,
        status_code=status.HTTP_200_OK
    )

    return response
    