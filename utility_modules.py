from fastapi import FastAPI,HTTPException,Depends,status

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel , EmailStr
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext

from typing import Annotated
from utility_func import *
from schemas import *