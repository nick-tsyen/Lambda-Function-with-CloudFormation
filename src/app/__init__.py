import os
from typing import Optional
import base64
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import pyotp
from jose import jwt, JWTError
import smtplib
from mangum import Mangum

# secret = os.environ.get('BASE32KEY')
SALT = os.environ.get('MY_SALT')
SECRET_KEY = os.environ.get('MY_SECRET_KEY')
ALGORITHM = 'HS256'

app = FastAPI()

oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token')


def send_email(otp: str, email: str, title: str = "OTP Code"):
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(os.environ.get('EMAIL_SENDER'), os.environ.get('EMAIL_PASSWORD'))

        sent_from = os.environ.get('EMAIL_SENDER')
        to = email
        subject = title
        text = otp
        message = f'Subject: {subject}\n\n{text}'
        server.sendmail(sent_from, to, message)
        return "Email succeed"
    except:
        return "Email failed"


# region <Create and Decode JWT Token>
def create_access_token(email, expire_delta: Optional[timedelta] = None):
    """
    Generate JWT token by encoding the email
    :param email: str,
    :param expire_delta: timedelta,
    :return: JTW token
    """
    encode = {"sub": email}
    if expire_delta:
        expire = datetime.utcnow() + expire_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    encode.update({"exp": expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str = Depends(oauth2_bearer)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=404, detail='invalid token')
        return email
    except JWTError:
        raise HTTPException(status_code=404, detail='invalid token')

# endregion


@app.get("/")
async def get_root():
    return {"message": f"This API server is working correctly. See Docs."}


@app.post("/get-otp")
async def get_otp_by_email(email):
    secret = base64.b32encode((email + SALT).encode()).decode()
    totp = pyotp.TOTP(secret, interval=300)
    otp = totp.now()
    email_status = send_email(otp, email)
    return {"message": f"Email sent to {email} with OTP {otp} | {email_status}"}


@app.post("/get-token")
async def get_token_by_otp(email, otp):
    secret = base64.b32encode((email + SALT).encode()).decode()
    totp = pyotp.TOTP(secret, interval=300)
    if totp.verify(otp):
        token = create_access_token(email)
    else:
        raise HTTPException(status_code=404, detail='invalid OTP')
    return token


@app.post("/{token}/greet")
async def get_message(token: str):
    email = decode_access_token(token)
    if email is not None:
        return {"message": f"Success as {email}"}
    else:
        raise HTTPException(status_code=404, detail='unauthenticated email')


handler = Mangum(app)