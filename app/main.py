import logging
import os
import random
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from kavenegar import *

from . import log

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09125e094faa6ca2556d818166b7a0063493f70f9f6f0f4caaacf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

OTP_RESEND_TIMEOUT = 120
KAVE_ENABLED = True
otps = {}

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]


@app.get("/otp/send_otp/{phone_num}")
def send_otp(phone_num: str):
    # ToDo: We have to normalize all type of phone_num (e.g. +989121002003, 09121002003, 9121002003)
    # before stroing/searching them in otps dictionary.
    try:
        import json
    except ImportError:
        import simplejson as json
    logging.debug("OTPs: {}".format(str(otps)))
    kavehnegar_apikey = os.environ['kavehnegar_apikey']
    prev_otp_data = otps.get(phone_num)
    if prev_otp_data:
        if prev_otp_data['timestamp'] > datetime.now() - timedelta(seconds=OTP_RESEND_TIMEOUT):
            return {"msg": "No SMS was sent! Since we have sent an SMS to this number recently!"}
        else:
            otps.pop(phone_num)
    rand_otp = random.randint(10100, 99900)
    otp_value = {"otp": rand_otp, "timestamp": datetime.now()}
    otps[phone_num] = otp_value
    logging.debug("The ({0}:{1}) pair inserted into OTPs".format(phone_num, otp_value))
    if KAVE_ENABLED:
        try:
            api = KavenegarAPI(kavehnegar_apikey)
            params = {
                'receptor': str(phone_num),
                'template': 'CoinJet',
                'token': str(rand_otp),
                'type': 'sms',
            }
            logging.debug("Params: {}".format(params))
            rsp = str(api.verify_lookup(params))
            logging.info("rsp: {}".format(rsp))
        except APIException as e:
            exp = str(e)
            exp_decode = exp.encode('latin1').decode('unicode_escape').encode('latin1').decode('utf8')
            logging.error("exp_decode: {}".format(exp_decode))
        except HTTPException as e:
            logging.error(str(e))
    else:
        logging.debug("kave_enabled is False")
    return {"msg": "A SMS was sent successfully!"}


@app.get("/otp/check_otp/{phone_num}/{otp}")
def check_otp(phone_num: str, otp: int):
    logging.debug("OTPs: {}".format(str(otps)))
    prev_otp_data = otps.get(phone_num)
    if prev_otp_data:
        if prev_otp_data['timestamp'] > datetime.now() - timedelta(seconds=OTP_RESEND_TIMEOUT) and \
                prev_otp_data['otp'] == otp:
            return {"msg": "True"}
        else:
            return {"msg": "False"}
    else:
        return {'msg': 'False'}
