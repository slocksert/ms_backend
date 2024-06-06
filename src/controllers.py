import io
from fastapi import File, UploadFile, status, APIRouter, Depends, Response, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm

import uuid
from sqlmodel import Session

import models
from schemas import UpdatePassword, UpdateUser, GetUser, UpdateStatus
from repository import AuthUser
from depends import token_verifier_home, verify_adm
from database import get_session

register = APIRouter(prefix='/user')
login = APIRouter(prefix='/user')
index = APIRouter(dependencies=[Depends(token_verifier_home)])
adm_route = APIRouter(dependencies=[Depends(verify_adm)])
repository = AuthUser()

@register.post('/register')
async def create_user(user: models.Users,session: Session = Depends(get_session)):
    repository.user_register(user=user, session=session)
    
    return JSONResponse(
        content=({
            "msg": "User created succesfully"
        }), status_code=status.HTTP_201_CREATED
    )

@login.post('/login')
async def user_login(response: Response, 
                     request_form_user: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):

    user = models.Users(
        email=request_form_user.username,
        password=request_form_user.password
    )

    data = repository.user_login(user_model=user, session=session)

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

@index.post('/user/contact')
async def contact(request:Request, form:models.Contact, session:Session = Depends(get_session)):
    cookie = request.headers.get("Authorization").split(' ')
    cookie = cookie[1]
    
    repository.send_contact(cookie=cookie, session=session, form=form)

    return JSONResponse(
        content={"message":"Contact form sent"}, 
        status_code=status.HTTP_200_OK
    )

@index.post('/user/sendimage')
async def send_image(request:Request, session: Session = Depends(get_session), file:UploadFile = File(...)):
    image_bytes = await file.read()
    filename = f"{uuid.uuid4()}.jpg"
    
    repository.write_image(filename=filename, image_bytes=image_bytes)
    
    cookie = request.headers.get("Authorization").split(' ')
    cookie = cookie[1]
    
    response = JSONResponse(
        content={"message":"Profile picture updated successfuly."}, 
        status_code=status.HTTP_201_CREATED
    )

    repository.send_uuid_image_to_db(filename, cookie, session)
    return response

@index.get('/user/getimage')
async def get_image(request:Request, session:Session = Depends(get_session)):
    cookie = request.headers.get("Authorization").split(' ')
    cookie = cookie[1]

    image_uuid = repository.get_image_name(cookie=cookie, session=session)

    return JSONResponse(
        content={"image_uuid":image_uuid}, 
        status_code=status.HTTP_200_OK
    )

@index.get('/user/getimagefile')
async def get_file(request:Request, session:Session = Depends(get_session)):
    cookie = request.headers.get("Authorization").split(' ')
    cookie = cookie[1]

    image_uuid = repository.get_image_name(cookie=cookie, session=session)
    image_path = (
        "storage/pictures/NoImage.png"
        if image_uuid == "NoImage"
        else f"storage/pictures/{image_uuid}"
    )

    with open(image_path, "rb") as file:
        image_binary = file.read()

    return StreamingResponse(io.BytesIO(image_binary), media_type="image/png")

@index.put('/user/updateuser')
async def update_user(request:Request, user:UpdateUser, session: Session = Depends(get_session)):
    cookie = request.headers.get("Authorization").split(' ')
    cookie = cookie[1]

    repository.update_username(session=session, cookie=cookie, name=user.new_username)

    return JSONResponse(
        content={"message":"Username updated successfully."},
        status_code=status.HTTP_200_OK)

@index.put('/user/updatepwd')
async def update_password(request:Request, user:UpdatePassword, session:Session = Depends(get_session)):
    cookie = request.headers.get("Authorization").split(' ')
    cookie = cookie[1]
    data = {
        "new_password":user.new_password,
        "old_password":user.old_password
    }
    repository.update_password(data=data, session=session, cookie=cookie)

    return  JSONResponse(
        content="Password has been changed.", 
        status_code=status.HTTP_200_OK
    )

@index.get('/user/getinfo')
async def get_user_info(request:Request, session:Session = Depends(get_session)):
    cookie = request.headers.get("Authorization").split(' ')
    cookie = cookie[1]

    user = repository.get_info(cookie=cookie, session=session)

    return JSONResponse(
        content=user,
        status_code=status.HTTP_200_OK
    )

@adm_route.post('/user/adm/deleteuser')
async def delete_user(user:GetUser, session:Session = Depends(get_session)):
    repository.delete_user(user.username, session)

    return JSONResponse(
        content={"message": f"User {user.username} deleted successfully."},
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
    users = repository.get_users(session)

    return JSONResponse(
        content=users,
        status_code=status.HTTP_200_OK
    )

@adm_route.get('/user/adm/getuser')
async def get_user_by_username(user:GetUser, session: Session = Depends(get_session)):
    user = repository.get_user_by_username(user.username, session)

    return JSONResponse(
        content=user,
        status_code=status.HTTP_200_OK
    )

@adm_route.put('/user/adm/updatestatus')
async def update_is_active(user: UpdateStatus, session:Session = Depends(get_session)):
    repository.update_status(username=user.username, session=session, status=user.status)
    state = "Active" if user.status else "Inactive"
    content = {"message": f"{user.username} is now " + state}

    return JSONResponse(
        content=content,
        status_code=status.HTTP_200_OK
    )