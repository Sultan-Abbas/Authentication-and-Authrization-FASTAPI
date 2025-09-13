from utility_modules import *
from utility_func import *
from database import get_db,User
from sqlalchemy.orm import Session

app = FastAPI()

SECRET_KEY="40a2ca550d0cd1c80855d2d026d77861150787edcb63f795ac944a89078e0904"
ALGORITHM="HS256"   
ACCESS_TOKEN_EXPIRE_MINUTES=30
fake_users = {}
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.Username == form_data.username).first()
    
    if not user or not hash_password_check(form_data.password, user.Password_user):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_Token(
        data_of_user={"username": user.Username, "email": user.Email}
    )
    print("Login Successful")
    return {"access_token": access_token, "token_type": "bearer"}
 
@app.post("/register")
async def register(user: RegisterUser, db: Session =  Depends(get_db)):
    existing_user= db.query(User).filter(user.username==User.Username).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )
    
    hashed_password = hash_password(user.password)

    new_user = User(
        Username = user.username,
        Password_user = hashed_password,
        Email =  user.email)
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully!"}   