#!/usr/bin/env python3
"""hash password module"""
import bcrypt

def hash_password(password: str) -> bytes:
    """take an str password convert it to bytes and hash it"""
    pw_bytes = password.encode()
    hashed_pw = bcrypt.hashpw(pw_bytes, bcrypt.gensalt())
    return hashed_pw


def is_valid(hashed_password: bytes, password: str) -> bool:
    """check if hashed_pw is pw"""
    return bcrypt.checkpw(password.encode(), hashed_password)
