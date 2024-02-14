#!/usr/bin/env python3
"""
module for Auth class
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """ manage API authentication """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Check whether an endpoint requires auth or not """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        else:
            for i in excluded_paths:
                if i.startswith(path) or path.startwith(i):
                    return False
                if i[-1] == "*":
                    if path.startswith(i[:-1]):
                        return False
        return True

    def authorization_header(self, request=None) -> str:
        """ handling authorization header """
        if request is None:
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ checking current user """
        return None
