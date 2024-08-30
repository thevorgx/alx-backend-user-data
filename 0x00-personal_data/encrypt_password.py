#!/usr/bin/env python3
"""hash password module"""
from bcrypt import hashpw, gensalt, checkpw


def hash_password(password: str) -> bytes:
    """take an str password convert it to bytes and hash it"""
    pw_bytes = password.encode()
    hashed_pw = hashpw(pw_bytes, gensalt())
    return hashed_pw


def is_valid(hashed_password: bytes, password: str) -> bool:
    """check if hashed_pw is pw"""
    pw_bytes = password.encode()
    check = checkpw(pw_bytes, hashed_password)
    return check
