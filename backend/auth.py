import datetime

import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext


class Authhandler:
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret = "FARMSTACKsecretString"

    # hash password
    def get_password_hash(self, password: str) -> str:
        hashed_password = self.pwd_context.hash(password)
        return hashed_password

    def verify_password(self, plain_password, hashed_password) -> bool:
        matched = self.pwd_context.verify(plain_password, hashed_password)
        return matched

    # token
    def encode_token(self, user_id: str, username: str):
        payload = {
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=30),
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "sub": {"user_id": user_id, "username": username},
        }

        token = jwt.encode(payload, self.secret, "HS256")
        return token

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload["sub"]

    def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)):
        sub = self.decode_token(auth.credentials)
        return sub
