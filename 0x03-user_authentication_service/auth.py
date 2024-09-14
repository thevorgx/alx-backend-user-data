#!/usr/bin/env python3
"""Auth module"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Hash a password using bcrypt"""
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_pw


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """register new user"""
        try:
            existing_user = self._db.find_user_by(email=email)
            if existing_user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass

        hashed_password = _hash_password(password)
        new_user = self._db.add_user(
            email=email,
            hashed_password=hashed_password.decode('utf-8'))

        return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Check if a login is valid by verifying the email and password"""
        try:
            user = self._db.find_user_by(email=email)
            pw = password.encode('utf-8')
            user_h = user.hashed_password.encode('utf-8')
            if bcrypt.checkpw(pw, user_h):
                return True
        except NoResultFound:
            return False
        return False
