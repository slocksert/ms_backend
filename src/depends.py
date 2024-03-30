from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session

from repository import AuthUser
from database import get_session

au = AuthUser()
oauth_scheme_home = OAuth2PasswordBearer(tokenUrl='/user')
oauth_scheme_adm = OAuth2PasswordBearer(tokenUrl='/user/adm')

#Dependecy that verifies the access_token 
def token_verifier_home(token = Depends(oauth_scheme_home), session: Session = Depends(get_session)) -> None:
    au.verify_token(token, session=session)

#Dependecy that verifies if the access token payload 'sub' is equal to admin
def verify_adm(token = Depends(oauth_scheme_adm), session: Session = Depends(get_session)) -> None:
    au.verify_admin(token, session=session)