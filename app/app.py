import logging
import os
from datetime import datetime, timedelta
import random

from fastapi import Depends, FastAPI, HTTPException
from starlette import status

from .config import DEFAULT_SETTINGS
from .crud_models import UserCreate, UserResponse
from .db import get_db, Base, engine
from .db_actions import get_user, create_user, check_user
from .security import manager, verify_password
from . import log, utils

from kavenegar import KavenegarAPI, APIException

OTP_RESEND_TIMEOUT = 120
KAVE_ENABLED = True
otps = {}

app = FastAPI()


@app.on_event("startup")
def setup():
    print("Creating db tables...")
    Base.metadata.create_all(bind=engine)
    print(f"Created {len(engine.table_names())} tables: {engine.table_names()}")


@app.post("/auth/register")
def register(user: UserCreate, db=Depends(get_db)):
    user.phone = utils.normalize_phone_num(user.phone)
    res = check_user(user.phone, user.email, user.username)
    if res[0]:
        raise HTTPException(status_code=400, detail=res[1])
    else:
        db_user = create_user(db, user)
        return UserResponse(id=db_user.id, email=db_user.email)


@app.post(DEFAULT_SETTINGS.token_url + "/{phone_num}/{otp}")
def login(phone_num: str, otp: int):
    phone_num = utils.normalize_phone_num(phone_num)
    if check_otp(phone_num, otp)['msg'] == 'False':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect OTP")
    user = get_user(phone_num)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="There is no user with this phone number!")
    # ToDo: Add expires_delta to create_access_token
    access_token = manager.create_access_token(data=dict(sub=user.phone))
    return {'access_token': access_token, 'token_type': 'Bearer'}


@app.get("/auth/is_login")
def is_login(user=Depends(manager)):
    return {"status": "True"}


@app.post("/otp/send_otp/{phone_num}")
def send_otp(phone_num: str):
    # ToDo: We have to normalize all type of phone_num (e.g. +989121002003, 09121002003, 9121002003)
    # before stroing/searching them in otps dictionary.
    phone_num = utils.normalize_phone_num(phone_num)
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


@app.post("/otp/check_otp/{phone_num}/{otp}")
def check_otp(phone_num: str, otp: int):
    phone_num = utils.normalize_phone_num(phone_num)
    logging.debug("OTPs: {}".format(str(otps)))
    prev_otp_data = otps.get(phone_num)
    if prev_otp_data:
        if prev_otp_data['timestamp'] > datetime.now() - timedelta(seconds=OTP_RESEND_TIMEOUT) and \
                prev_otp_data['otp'] == otp:
            logging.debug("OTP is valid")
            return {"msg": "True"}
        else:
            logging.debug("OTP is not valid")
            return {"msg": "False"}
    else:
        logging.debug("We had no OTP for this number")
        return {'msg': 'False'}
