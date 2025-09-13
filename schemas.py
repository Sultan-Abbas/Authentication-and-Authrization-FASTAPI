
from pydantic import BaseModel, EmailStr

class user(BaseModel):
    username: str
    password: str
    email:  EmailStr | None = None
    disabled: bool | None = None
    
class Token(BaseModel):
    access_token: str
    token_type: str
    
class RegisterUser(BaseModel):
    username: str
    password: str
    email: EmailStr
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    