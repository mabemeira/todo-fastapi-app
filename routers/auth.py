from datetime import timedelta, datetime
from typing import Annotated
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from dotenv import load_dotenv
import os

load_dotenv()

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

class CreateUserRequest(BaseModel):
    email: str
    username: str
    first_name: str
    last_name: str
    password: str
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency,
                    create_user_request: CreateUserRequest):
    create_user_model = Users(
        email = create_user_request.email,
        username = create_user_request.username,
        first_name = create_user_request.first_name,
        last_name = create_user_request.last_name,
        role = create_user_request.role,
        hashed_password = bcrypt_context.hash(create_user_request.password),
        is_active = True
    )

    db.add(create_user_model)
    db.commit()

def create_acess_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username,'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithm=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')

        if username is None or user_id is None:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, 
                                detail='Could not validate user')   
        return {'username': username, 'id': user_id}
    
    except JWTError:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, 
                                detail='Could not validate user') 


@router.post("/token", response_model=Token)
async def login_user_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                    db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    
    if not user:
        return HTTPException(status_code=HTTP_401_UNAUTHORIZED, 
                                detail='Could not validate user') 
    
    token = create_acess_token(user.username, user.id, timedelta(minutes=20))
    return {"access_token": token, "token_type": "Bearer"}