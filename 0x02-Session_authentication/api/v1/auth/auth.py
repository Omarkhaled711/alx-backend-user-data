#!/usr/bin/env python3
"""
module for Auth class
"""
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """ manage API authentication """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Check whether an endpoint requires auth or not """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        else:
            if path[-1] != '/':
                path += '/'
            for excluded in excluded_paths:
                if len(excluded) == 0:
                    continue
                if (excluded[-1] == '*'):
                    excluded = excluded[:-1]
                if path == excluded or path.startswith(excluded):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """ handling authorization header """
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """ checking current user """
        return None

    def session_cookie(self, request=None):
        """returns a cookie value from a request"""
        if request is None:
            return None
        session_name = getenv("SESSION_NAME")
        return request.cookies.get(session_name)
