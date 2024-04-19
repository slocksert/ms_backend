from typing import Literal
from sqlmodel import Session, select, SQLModel
from passlib.context import CryptContext
from decouple import config
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import re
import os
import uuid 

from models import Roles, Users, Contact
from ext import len_password, email_not_valid,existent_email, no_cnpj, cpf_len_and_is_digit, incorrect_user, incorrect_password, jwt_error, unauthorized, image_error, existent_cnpj, invalid_username, existent_password, wrong_password

SECRET_KEY = config("SECRET_KEY")
ALGORITHM = config("ALGORITHM")

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
        name="admin", 
        email="admin@admin.com",
        password=crypt_context.hash(config("ADMIN_PWD")), 
        role_id=role_admin.id,
        uuid=str(uuid.uuid4())
    )

    session.add(admin)
    session.commit()

# Class that contains all the functions called by the routes
class AuthUser:
    def __init__(self):
        self.crypt_context = crypt_context

    def __decode_jwt(self, cookie) -> str:
        try:
            payload = jwt.decode(cookie, SECRET_KEY, algorithms=[ALGORITHM])
            sub = payload["sub"]
            return sub
        
        except JWTError:
            raise jwt_error()
    
    #Email validator using regular expressions 
    def __email_is_valid(self, email: str) -> bool:
        regex = r"\b[A-Za-z0-9._%+-]+@[A-za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"

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
    
    def __get_curent_by(self, value:str, table:SQLModel, 
                        session:Session, 
                        param:Literal["uuid", "name", "cnpj", "email"] = "uuid"
        ) -> Users | Contact:
        
        statement = select(table).where(getattr(table, param) == value)
        data = session.exec(statement).first()

        if param != "cnpj":
            if not data:
                raise incorrect_user()

            if not data.is_active:
                raise incorrect_user()
        
        return data

    def user_register(self, user: Users, session:Session) -> None:
        new_user = Users(
            name=user.name, 
            password=self.crypt_context.hash(user.password), 
            email=user.email,
            uuid=str(uuid.uuid4())
        )

        email_query = select(Users).where(Users.email == user.email)
        email = session.exec(email_query).first()
        
        if len(user.password) < 8:
            raise len_password()
        
        if not self.__email_is_valid(user.email):
            raise email_not_valid()
        
        if email:
            raise existent_email()

        session.add(new_user)
        session.commit()

    def user_login(self, user_model: Users, session:Session) -> dict:
        is_email = self.__email_is_valid(user_model.email)

        if not is_email:
            return email_not_valid()

        user = self.__get_curent_by(
            table=Users,
            param="email",
            value=user_model.email,
            session=session
        )
        
        if not self.crypt_context.verify(user_model.password, user.password):
            raise incorrect_password()

        return self.__new_jwt(uuid=user.uuid)

    def verify_token(self, cookie:str, session:Session) -> None:
        try:
            uuid = self.__decode_jwt(cookie)
            user = self.__get_curent_by(
                table=Users,
                param="uuid",
                value=uuid,
                session=session
            )

            if user is None:
                raise jwt_error()
            
        except JWTError:
            raise jwt_error()

    def verify_admin(self, cookie:str, session:Session) -> None:
        try:
            uuid = self.__decode_jwt(cookie)
            user = self.__get_curent_by(
                table=Users,
                param="uuid",
                value=uuid,
                session=session
            )

            if user.id != 1:
                raise unauthorized()

        except JWTError:
            raise jwt_error()
    
    def write_image(self, filename:str, image_bytes:bytes) -> None:
        directory = "../storage/pictures"
        
        os.makedirs(directory, exist_ok=True)
        
        file_path = os.path.join(directory, filename)
        with open(file_path, "wb") as f:
            f.write(image_bytes)
        
        image_path = os.path.exists(file_path)
            
        if not image_path:
            raise image_error()

    def delete_image(self, filename:str) -> None:
        file_path = os.path.join("../storage/pictures", filename)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} does not exists!")
        os.remove(file_path)

    def send_uuid_image_to_db(
            self, filename:str, cookie:str, session:Session
            ) -> None:
        try:
            uuid = self.__decode_jwt(cookie)
            user = self.__get_curent_by(
                table=Users,
                session=session,
                param="uuid",
                value=uuid
            )

            if user:
            # Remove the old image file if it exists
                if user.image_uuid != "Sem imagem":
                    old_image_file = user.image_uuid
                    os.remove(os.path.join("../storage/pictures", old_image_file))

                # Update the image filename in the database
                user.image_uuid = filename
                session.add(user)
                session.commit()
                
        except JWTError:
            raise jwt_error()
        except Exception:
            self.delete_image(filename)

    def get_users(self, session:Session) -> list:
        statement = select(Users)
        results = session.exec(statement)

        users = []

        for user in results:
            user_dict = user.model_dump()
            user_dict["registered_at"] = str(user_dict["registered_at"])
            users.append(user_dict)
        
        return users
    
    def get_user_by_username(self, name:str, session:Session) -> dict:
        user = self.__get_curent_by(
            table=Users,
            session=session,
            param="name",
            value=name
        )

        user = user.model_dump()
        user["registered_at"] = str(user["registered_at"])

        return user
    
    def update_username(self, session:Session, cookie:str, name:str) -> None:
        uuid = self.__decode_jwt(cookie=cookie)
        user = self.__get_curent_by(
            table=Users,
            session=session,
            param="uuid",
            value=uuid
        )
        user.name = name
        
        session.add(user)
        session.commit()
        session.refresh(user)

    def delete_user(self, name:str, session:Session):
        user = self.__get_curent_by(
            table=Users,
            session=session,
            param="name",
            value=name
        )
        
        session.delete(user)
        session.commit()
    
    def update_password(self, data:dict, cookie:str, session:Session) -> None:
        uuid = self.__decode_jwt(cookie)
        user = self.__get_curent_by(session=session, table=Users, value=uuid, param="uuid")

        if not crypt_context.verify(data["old_password"], user.password):
            raise wrong_password()

        if not user:
            raise invalid_username()

        if crypt_context.verify(data["new_password"], user.password):
            raise existent_password()
        
        if len(data["new_password"]) < 10:
            raise len_password()
        
        user.password = crypt_context.hash(data["new_password"])
        session.add(user)
        session.commit()
        session.refresh(user)

    def update_status(self, status:bool, name:str, session:Session) -> None:
        user = self.__get_curent_by(
            table=Users,
            session=session,
            param="name",
            value=name
        )

        if type(status) != bool:
            raise Exception
        
        user.is_active = status
        session.add(user)
        session.commit()
        session.refresh(user)

    def get_image_name(self, session:Session, cookie:str) -> str:
        uuid = self.__decode_jwt(cookie=cookie)
        user = self.__get_curent_by(
                table=Users,
                session=session,
                param="uuid",
                value=uuid
        )

        if not user:
            raise incorrect_user()
        
        return user.image_uuid
    
    def send_contact(self, session:Session, cookie:str, form:Contact) -> None:
        new_form = Contact(
            adress=form.adress,
            phone=form.phone,
            cep=form.cep,
            city=form.city,
            cnpj=form.cnpj,
            company_name=form.company_name,
            complement=form.complement,
            district=form.district,
            state=form.state,
            description=form.description
        )

        uuid = self.__decode_jwt(cookie=cookie)
        user = self.__get_curent_by(
            table=Users, 
            value=uuid, 
            param="uuid", 
            session=session
        )
        cnpj = self.__get_curent_by(
            table=Contact,
            value=form.cnpj,
            param="cnpj", 
            session=session
        )

        if not user:
            raise incorrect_user()
        
        if not form.cnpj:
            raise no_cnpj()
        
        if len(form.cnpj) < 14 or not form.cnpj.isdigit():
            raise cpf_len_and_is_digit()
        
        if cnpj:
            raise existent_cnpj()
        
        session.add(new_form)
        session.commit()