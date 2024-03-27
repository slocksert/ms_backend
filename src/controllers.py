from fastapi import status, APIRouter, Depends
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

import models
from repository import AuthUser
from depends import token_verifier_home, verify_adm

register = APIRouter(prefix='/user')
login = APIRouter(prefix='/user/auth')
index = APIRouter(dependencies=[Depends(token_verifier_home)])
adm_route = APIRouter(dependencies=[Depends(verify_adm)])

@register.post('/register')
async def create_user(user: models.Users):
   
    au = AuthUser()
    au.user_register(user=user)
    
    return JSONResponse(
        content=({
            "msg": "User created succesfully"
        }), status_code= status.HTTP_201_CREATED
    )

@login.post('/login')
async def user_login(request_form_user: OAuth2PasswordRequestForm = Depends()):

    user = models.Users(
        username=request_form_user.username,
        password=request_form_user.password
    )

    au = AuthUser()
    auth_data = au.user_login(user=user)

    return JSONResponse(
        content=auth_data, status_code= status.HTTP_200_OK
    )

@index.get('/home')
async def home():
    return {"msg":"Authorized"}

@adm_route.get('/user/adm')
async def adm():
    return {"msg":"Authorized"}