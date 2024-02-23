#!/usr/bin/env python3
"""
Testing module
"""
import requests

local_host = 'http://localhost:5000'
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


def register_user(email: str, password: str) -> None:
    """ Test user registration """
    form_data = {
        "email": email,
        "password": password
    }
    response = requests.post(f'{local_host}/users', data=form_data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}


def log_in_wrong_password(email: str, password: str) -> None:
    """ Test log in with wrong password """
    form_data = {
        "email": email,
        "password": password
    }
    response = requests.post(f'{local_host}/sessions', data=form_data)
    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """ Test login """
    form_data = {
        "email": email,
        "password": password
    }
    response = requests.post(f'{local_host}/sessions', data=form_data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "logged in"}
    return response.cookies.get("session_id")


def profile_unlogged() -> None:
    """ Test profile with no login """
    session_cookies = {
        "session_id": ""
    }
    response = requests.get(f'{local_host}/profile', cookies=session_cookies)
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """ Test profile when logged in """
    session_cookies = {
        "session_id": session_id
    }
    response = requests.get(f'{local_host}/profile', cookies=session_cookies)

    assert response.status_code == 200
    assert response.json() == {"email": EMAIL}


def log_out(session_id: str) -> None:
    """ Test logout """
    session_cookies = {
        "session_id": session_id
    }
    response = requests.delete(
        f'{local_host}/sessions', cookies=session_cookies)
    assert response.status_code == 200
    assert response.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """ Test password reset token """
    form_data = {
        "email": email
    }
    response = requests.post(
        f'{local_host}/reset_password', data=form_data)
    assert response.status_code == 200
    reset_token = response.json().get("reset_token")
    assert response.json() == {"email": email, "reset_token": reset_token}
    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """ Test password reset """
    form_data = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password
    }
    response = requests.put(
        f'{local_host}/reset_password', data=form_data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
