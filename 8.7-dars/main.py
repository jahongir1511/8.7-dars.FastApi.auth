from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from models import User

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_users_db = {}

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

@app.post("/signup")
async def signup(user: User):
    if user.username in fake_users_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
    hashed_password = hash_password(user.password)
    fake_users_db[user.username] = hashed_password
    return {"username": user.username}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_password = fake_users_db.get(form_data.username)
    if not user_password or not verify_password(form_data.password, user_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return {"access_token": form_data.username, "token_type": "bearer"}

@app.get("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    return {"message": "Logged out successfully"}
