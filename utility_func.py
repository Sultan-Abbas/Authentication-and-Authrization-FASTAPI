from fastapi import FastAPI,HTTPException,Depends,status

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from jwt.exceptions import InvalidTokenError
from jose import JWTError
from pydantic import BaseModel , EmailStr
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext

from typing import Annotated
from utility_func import *
from schemas import *
from database import get_db,User
from sqlalchemy.orm import Session


from passlib.context import CryptContext
SECRET_KEY = "40a2ca550d0cd1c80855d2d026d77861150787edcb63f795ac944a89078e0904"
ALGORITHM = "HS256" 
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme= OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
 
def hash_password(password:str):
    return pwd_context.hash(password)


def hash_password_check(plain_password:str, hashed_password:str):
    return pwd_context.verify(plain_password, hashed_password)

def create_Token(data_of_user:dict):
    to_encode = data_of_user.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire , "sub": data_of_user.get("username")})   
    
    encoded_jwt= jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt  

def verify_Token(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")

# def get_current_user(token: str = Depends(oauth2_scheme)):
#     payload = verify_Token(token)
#     username: str = payload.get("sub")
#     if username in fake_users:
#         user = fake_users[username]
#         return user
#     else:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.Username == username).first()
    if user is None:
        raise credentials_exception
    return user