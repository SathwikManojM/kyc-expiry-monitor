from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from pwdlib import PasswordHash

SECRET_KEY = os.environ.get("KYC_SECRET_KEY", "local-demo-secret-change-before-deployment")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = int(os.environ.get("KYC_TOKEN_EXPIRE_MINUTES", "30"))
_password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hash.verify(password, password_hash)
    except (ValueError, TypeError):
        return False


def create_access_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": username, "exp": expire, "role": "admin"}, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload if payload.get("role") == "admin" and payload.get("sub") else None
    except JWTError:
        return None
