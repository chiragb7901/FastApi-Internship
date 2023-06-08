from fastapi import Depends, FastAPI, HTTPException,Body
from sqlalchemy.orm import Session
import models
from pydantic import BaseModel, Field
from database import SessionLocal, engine
from passlib.context import CryptContext
from datetime import datetime, timedelta
import secrets
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.models import APIKey
from fastapi.security import APIKeyHeader


app = FastAPI()
models.Base.metadata.create_all(bind=engine)


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

class Users(BaseModel):
    user_name: str=Field(min_length=1)
    email: str = Field(min_length=1)
    # expiry_date: str = Field(min_length=1)
    # api_key:str = Field(min_length=1)

class UsersReturn(BaseModel):
    user_name: str=Field(min_length=1)
    email: str = Field(min_length=1)
    expiry_date: str = Field(min_length=1)
    api_key:str = Field(min_length=1)

class UserAuthentication(BaseModel):
    api_key: str

api_key = APIKeyHeader(name="X-API-Key", auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.post("/register")
def create_user(user: Users, db: Session = Depends(get_db)): 
    user_model = models.User()
    user_model.user_name = user.user_name
    user_model.email = user.email

    expiry_date = datetime.now() + timedelta(days=365)
    user_model.expiry_date= expiry_date

    api_key = secrets.token_hex(5)
    hashed_api_key = pwd_context.hash(api_key)
    user_model.api_key = hashed_api_key

    db.add(user_model)
    db.commit()
    response_object = {"data":user,
                       "Api_key":hashed_api_key}
    return response_object



async def validate_api_key(api_key: str = Depends(api_key)):
    if api_key != "$2b$12$q5yrjysxc0xlL7cFDlDwp.Y3..uhzEjcJVOql1vybIt/qD3M4AbJW": 
        raise HTTPException(status_code=402, detail="Invalid API key")


@app.get("/user/authenticate")
async def api_key_validation(user: UserAuthentication,api_key: str = Depends(validate_api_key),db: Session = Depends(get_db)):
    user1 = db.query(models.User).filter(user.user_name==models.User.user_name).first()
    if user.username not in db:
        raise HTTPException(status_code=400, detail="User does not exist")

    if not pwd_context.verify(user1.api_key, user.api_key):
        raise HTTPException(status_code=402, detail="Invalid API key")
    
    if datetime.now() > user1.expiry_date:
        raise HTTPException(status_code=402, detail="API key expired")

    return {"message": "Authenticated successfully!"}


@app.get("/getUserData")
async def get_user_data(db: Session = Depends(get_db),api_key: str = Depends(validate_api_key)):
    user = db.query(models.User).filter(api_key==models.User.api_key).first()

    if user:
        data={"data":user}
        return data
    else:
        raise HTTPException(status_code=404, detail="User not found")

@app.get("/users/getAll")
def read_users( db: Session = Depends(get_db)):
    return db.query(models.User).all()

