#!/usr/bin/env python3
"""hash pw module"""
import bcrypt


def hash_password(password: str) -> bytes:
    """take a str password convert it to bytes and hash it"""
    pw_bytes = password.encode()
    hashed_pw = bcrypt.hashpw(pw_bytes, bcrypt.gensalt())
    return(hashed_pw)
