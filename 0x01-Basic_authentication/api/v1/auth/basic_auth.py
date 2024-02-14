#!/usr/bin/env python3
"""
Basic Authentication Module
"""
from api.v1.auth.auth import Auth
from base64 import b64decode
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """ Basic Authentication Class """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ Extracts the Base64 part of the Authorization Header """

        if authorization_header is None or \
                not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.split(' ', 1)[1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """ Decodes the base64 string """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            b64_encoded = base64_authorization_header.encode('utf-8')
            b64_decoded = b64decode(b64_encoded)
            b64_decoded = b64_decoded.decode('utf-8')
            return b64_decoded
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """
        Returns the user email and password based on the
        Base64 decoded value
        """

        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        return decoded_base64_authorization_header.split(':', 1)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Returns the User based on the email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            target_users = User.search({'email': user_email})
        except Exception:
            return None

        for user in target_users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ returns the User instance for a received request """
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None
        b64_encoded = self.extract_base64_authorization_header(auth_header)
        if not b64_encoded:
            return None
        b64_decoded = self.decode_base64_authorization_header(b64_encoded)
        if not b64_decoded:
            return None
        user_email, user_pwd = self.extract_user_credentials(b64_decoded)
        if not user_email or not user_pwd:
            return None
        return self.user_object_from_credentials(user_email, user_pwd)
