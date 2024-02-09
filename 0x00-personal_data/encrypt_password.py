#!/usr/bin/env python3
"""
Hashing and encrypting passwords module
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    function that expects one string argument name password and
    returns a salted, hashed password, which is a byte string.
    """
    pass_encod = password.encode()
    hash_pass = bcrypt.hashpw(pass_encod, bcrypt.gensalt())
    return hash_pass


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validates the provided password matches the hashed password """
    pass_encod = password.encode()
    return bcrypt.checkpw(pass_encod, hashed_password)
