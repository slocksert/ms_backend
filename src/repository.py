from models import Roles, Users
from database import engine

from sqlmodel import Session, select
from passlib.context import CryptContext
from decouple import config
from fastapi import HTTPException, status
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import re

session = Session(bind=engine)

SECRET_KEY = config('SECRET_KEY')
ALGORITHM = config('ALGORITHM')

crypt_context = CryptContext(schemes=["argon2"]) #Argon2 abstraction

#Create roles directly in the db
#This function is called in the migration
def create_roles():
    
    adm_role = Roles(name="admin")
    normal_role = Roles(name="normal_user")

    session.add_all([adm_role, normal_role])
    session.commit()

#Create the default admin user in the db
def create_admin():
    
    query = select(Roles).where(Roles.name == "admin")
    role_admin = session.exec(query).first()

    admin = Users(
        username="admin", 
        email="admin@admin.com",
        company_name="Maceió Segura",
        has_cnpj=False,
        password=crypt_context.hash("admin"), 
        role_id=role_admin.id
    )

    session.add(admin)
    session.commit()

#Email validator using regular expressions 
def email_is_valid(email: str) -> bool:
    regex = r'\b[A-Za-z0-9._%+-]+@[A-za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

    if re.fullmatch(regex, email):
        return True
    return False

# Class that contains all the functions called by the routes
class AuthUser:

    def __init__(self) -> None:
        self.session = session

    def user_register(self, user: Users):
        new_user = Users(
            username=user.username, 
            password=crypt_context.hash(user.password), 
            email=user.email,
            company_name=user.company_name,
            has_cnpj=user.has_cnpj
        )

        user_query = select(Users).where(Users.username == user.username)
        username = self.session.exec(user_query).first()

        email_query = select(Users).where(Users.email == user.email)
        email = self.session.exec(email_query).first()

        if username:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, 
                detail="Existent user"
            )
        
        elif len(user.password) < 10:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least  10 characters long"
            )
            
        
        elif not email_is_valid(user.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Invalid email format"
            )
        
        elif email:
            raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, 
            detail="Existent email"
        )

        self.session.add(new_user)
        self.session.commit()

    def user_login(self, user: Users, expires_in: int = 10080):
        is_email = email_is_valid(user.username)
        if is_email:
            user_query = select(Users).where(Users.email == user.username)
        else:
            user_query = select(Users).where(Users.username == user.username)

        username = self.session.exec(user_query).first()

        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Incorret username or password"
            )
        
        elif not crypt_context.verify(user.password, username.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Incorret username or password"
            )

        exp = datetime.now(timezone.utc) + timedelta(minutes=expires_in)
        payload = {
            "sub": user.username,
            "exp": exp
        }

        access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        return {
            "access_token": access_token,
            "exp": exp.isoformat()
        }

    def verify_token(self, access_token):
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            sub = payload["sub"]
            #Query that search for the user by decoding the access_token
            username_query = select(Users).where(Users.username == sub)
            username = session.exec(username_query).first()
            

            if username is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                    detail="Invalid access token")
            
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                detail="Invalid access token")

    def verify_admin(self, access_token):
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload["sub"] == "admin":
                return
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                     detail="Unauthorized", headers={"WWW-Authenticate": "Bearer"})

        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")