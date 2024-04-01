from sqlmodel import Session, select
from passlib.context import CryptContext
from decouple import config
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import re
import os

from models import Roles, Users
from ext import existent_user, len_password, email_not_valid,existent_email, no_cnpj, cpf_len_and_is_digit, incorrect_user, incorrect_password, jwt_error, unauthorized, image_error, existent_cnpj, invalid_username, existent_password, wrong_password

SECRET_KEY = config('SECRET_KEY')
ALGORITHM = config('ALGORITHM')

crypt_context = CryptContext(schemes=["argon2"]) #Argon2 abstraction

#Create roles directly in the db
#This function is called in the migration
def create_roles(session:Session) -> None:
    
    adm_role = Roles(name="admin")
    normal_role = Roles(name="normal_user")

    session.add_all([adm_role, normal_role])
    session.commit()

#Create the default admin user in the db
def create_admin(session:Session) -> None:
    
    query = select(Roles).where(Roles.name == "admin")
    role_admin = session.exec(query).first()

    admin = Users(
        username="admin", 
        email="admin@admin.com",
        company_name="Maceió Segura",
        password=crypt_context.hash(config("ADMIN_PWD")), 
        role_id=role_admin.id,
        adress="Praça da Sé",
        complement="Lado ímpar",
        district="Sé",
        city="São Paulo",
        state="SP",
        cep="01001000"
    )

    session.add(admin)
    session.commit()

# Class that contains all the functions called by the routes
class AuthUser:
    def __init__(self):
        self.crypt_context = crypt_context

    def __decode_jwt(self, access_token) -> str:
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            sub = payload['sub']
            return sub
        
        except JWTError:
            raise jwt_error()
    
    def __identify_user(self, sub:str, is_email:bool) -> str:
        if is_email:
            user_query = select(Users).where(Users.email == sub)
        else:
            user_query = select(Users).where(Users.username == sub)
        return user_query
    
    #Email validator using regular expressions 
    def __email_is_valid(self, email: str) -> bool:
        regex = r'\b[A-Za-z0-9._%+-]+@[A-za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

        if re.fullmatch(regex, email):
            return True
        return False

    def __new_jwt(self, uuid:str, expires_in:int = 120) -> dict:
        exp = datetime.now(timezone.utc) + timedelta(minutes=expires_in)
        payload = {
            "sub": uuid,
            "exp": exp
        }

        access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        return {
            "access_token": access_token,
            "exp": exp.isoformat()
        }    
    
    def __get_current_user(self, uuid:str, session:Session):
        statement = select(Users).where(Users.uuid==uuid)
        user =  session.exec(statement).first()

        if user.is_active != 1:
            raise incorrect_user()

        return user
    
    def __statement_by_user(self, username:str, session:Session):
        statement = select(Users).where(Users.username == username)
        user = session.exec(statement).first()
        return user

    def user_register(self, user: Users, session:Session) -> None:
        new_user = Users(
            username=user.username, 
            password=self.crypt_context.hash(user.password), 
            email=user.email,
            company_name=user.company_name,
            has_cnpj=user.has_cnpj,
            cnpj=user.cnpj,
            phone=user.phone
        )

        username = self.__statement_by_user(user.username, session)

        email_query = select(Users).where(Users.email == user.email)
        email = session.exec(email_query).first()

        cnpj_query = select(Users).where(Users.cnpj == user.cnpj)
        cnpj = session.exec(cnpj_query).first()

        if username:
            raise existent_user()
        
        elif len(user.password) < 10:
            raise len_password()
        
        elif not self.__email_is_valid(user.email):
            raise email_not_valid()
        
        elif email:
            raise existent_email()

        elif user.has_cnpj:
            if user.cnpj == None:
                raise no_cnpj()
                
            elif len(user.cnpj) != 14 or not user.cnpj.isdigit():
                raise cpf_len_and_is_digit()
        
            elif cnpj:
                raise existent_cnpj()

        session.add(new_user)
        session.commit()

    def user_login(self, user_model: Users, session:Session) -> dict:
        is_email = self.__email_is_valid(user_model.username)
        user_query = self.__identify_user(is_email=is_email, sub=user_model.username)

        user = session.exec(user_query).first()

        if not user or user.is_active != 1:
            raise incorrect_user()
        
        elif not self.crypt_context.verify(user_model.password, user.password):
            raise incorrect_password()

        return self.__new_jwt(uuid=user.uuid)

    def verify_token(self, access_token:str, session:Session) -> None:
        try:
            sub = self.__decode_jwt(access_token)
            user = self.__get_current_user(sub, session)

            if user is None:
                raise jwt_error()
            
        except JWTError:
            raise jwt_error()

    def verify_admin(self, access_token:str, session:Session) -> None:
        try:
            uuid = self.__decode_jwt(access_token)
            user = self.__get_current_user(uuid, session)

            if user.id != 1:
                raise unauthorized()

        except JWTError:
            raise jwt_error()
    
    def write_image(self, filename:str, image_bytes:bytes) -> None:
        directory = "storage/pictures"
        
        os.makedirs(directory, exist_ok=True)
        
        file_path = os.path.join(directory, filename)
        with open(file_path, 'wb') as f:
            f.write(image_bytes)

    def delete_image(self, filename:str) -> None:
        file_path = os.path.join("storage/pictures", filename)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f'File "{filename}" does not exists!')
        os.remove(file_path)

    def send_uuid_image_to_db(self, filename:str, access_token:str, session:Session) -> None:
        try:
            uuid = self.__decode_jwt(access_token)
            user = self.__get_current_user(uuid, session)

            if user:
            # Remove the old image file if it exists
                if user.image_uuid != "Sem imagem":
                    old_image_file = user.image_uuid
                    os.remove(os.path.join("storage/pictures", old_image_file))

                # Update the image filename in the database
                user.image_uuid = filename
                session.add(user)
                session.commit()
                
        except Exception as e:
            self.delete_image(filename)
            raise image_error(e)

    def get_users(self, session:Session) -> list:
        statement = select(Users)
        results = session.exec(statement)

        users = []

        for user in results:
            user_dict = user.model_dump()
            user_dict['registered_at'] = str(user_dict['registered_at'])
            users.append(user_dict)
        
        return users
    
    def get_user_by_username(self, username:str, session:Session) -> dict:
        user = self.__statement_by_user(username, session)

        if not user:
            raise invalid_username()

        user = user.model_dump()
        user['registered_at'] = str(user['registered_at'])

        return user
    
    def update_username(self, data:dict, session:Session):
        old_user = self.__get_current_user(data["uuid"], session)

        if not old_user:
            raise invalid_username()
        
        new_user = self.__get_current_user(data['new_username'], session)

        if new_user:
            raise existent_user()
        
        old_user.username = data["new_username"]
        
        session.add(old_user)
        session.commit()
        session.refresh(old_user)

    def delete_user(self, username:str, session:Session):
        user = self.__statement_by_user(username, session)
        
        if not user:
            raise invalid_username()
        
        session.delete(user)
        session.commit()

    def decode_jwt_and_verify(self, cookie:str, session:Session) -> str:
        uuid = self.__decode_jwt(cookie)
        user = self.__get_current_user(uuid, session)

        if not user:
            raise invalid_username()
        
        return uuid
    
    def update_password(self, data:dict, cookie:str, session:Session) -> None:
        uuid = self.__decode_jwt(cookie)
        user = self.__get_current_user(uuid, session)

        if not crypt_context.verify(data['old_password'], user.password):
            raise wrong_password()

        if not user:
            raise invalid_username()

        if crypt_context.verify(data['new_password'], user.password):
            raise existent_password()
        
        if len(data['new_password']) < 10:
            raise len_password()
        
        user.password = crypt_context.hash(data['new_password'])
        session.add(user)
        session.commit()
        session.refresh(user)

    def update_status(self, status:bool, username:str, session:Session):
        user = self.__statement_by_user(username, session)
        
        if not user:
            invalid_username()

        if type(status) != bool:
            raise Exception
        
        user.is_active = status
        session.add(user)
        session.commit()
        session.refresh(user)