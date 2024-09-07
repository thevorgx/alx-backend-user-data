#!/usr/bin/env python3
"""
BasicAuth
"""
import base64
from .auth import Auth
from typing import TypeVar

from models.user import User


class BasicAuth(Auth):
    """
    Basic Authentication implementation.
    """

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """Get Base64"""
        if (
            authorization_header is None
            or not isinstance(authorization_header, str)
        ):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        base64_part = authorization_header.replace("Basic ", "", 1)
        return base64_part

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """
        Decode the Base64 string
        """
        if (
            base64_authorization_header is None
            or not isinstance(base64_authorization_header, str)
        ):
            return None

        try:
            decoded_value = base64.b64decode(
                base64_authorization_header
            ).decode("utf-8")
            return decoded_value
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """
        Extract user email and password from the Base64 decoded value.
        """
        if (
            decoded_base64_authorization_header is None
            or not isinstance(decoded_base64_authorization_header, str)
        ):
            return None, None

        if ":" not in decoded_base64_authorization_header:
            return None, None

        user_email, user_password = decoded_base64_authorization_header.split(
            ":", 1
        )
        return user_email, user_password

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> User:
        """
        Return the User instance based on email and password.
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search(email=user_email)

        if not users:
            return None

        user_instance = users[0]

        if not user_instance.is_valid_password(user_pwd):
            return None

        return user_instance

    def current_user(self, request=None) -> User:
        """Retrieve the User instance for a request."""
        if not request:
            return None
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None
        base64_header = self.extract_base64_auth_header(auth_header)
        if not base64_header:
            return None
        decoded_header = self.decode_base64_auth_header(base64_header)
        if not decoded_header:
            return None
        email, password = self.extract_user_credentials(decoded_header)
        if not email or not password:
            return None
        return self.user_object_from_credentials(email, password)
