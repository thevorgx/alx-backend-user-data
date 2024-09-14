#!/usr/bin/env python3
"""Auth module"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid
from typing import Union
from flask import Flask, request, jsonify, abort, make_response


def _hash_password(password: str) -> bytes:
    """Hash a password using bcrypt"""
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_pw


def _generate_uuid() -> str:
    """Generate a new UUID and return its string representation"""
    return str(uuid.uuid4())


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

    def create_session(self, email: str) -> Union[None, str]:
        """Find user by email, create a session"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[None, User]:
        """retrieve user using session ID"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Hakai the user session by setting session ID to None"""
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """generate a reset password token for a user and return it"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError(f"User {email} does not exist")

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Update the user's password using the reset token"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(
                user.id,
                hashed_password=hashed_password.decode('utf-8'),
                reset_token=None)
        except NoResultFound:
            raise ValueError("Invalid reset token")
