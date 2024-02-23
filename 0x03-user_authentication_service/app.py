#!/usr/bin/env python3
"""
Flask app
"""
from auth import Auth
from flask import Flask, jsonify, request, abort, redirect
from flask.helpers import make_response

app = Flask(__name__)
AUTH = Auth()


@app.route('/')
def home() -> str:
    """
    returns a JSON payload
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def register_user() -> str:
    """
    Register a new user
    """
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(400)

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login() -> str:
    """
    login a user using email and password
    """
    email = request.form.get('email', "")
    password = request.form.get('password', "")
    if not AUTH.valid_login(email, password):
        abort(401)

    msg = {"email": email, "message": "logged in"}
    json_msg = jsonify(msg)
    session_id = AUTH.create_session(email)
    response = make_response(json_msg)
    response.set_cookie('session_id', session_id)
    return response


@app.route('/sessions', methods=['DELETE'])
def logout() -> str:
    """
    logout the user, and redirect to /
    """
    session_id = request.cookies.get("session_id", None)
    user = AUTH.get_user_from_session_id(session_id)

    if session_id is None or user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'])
def profile() -> str:
    """
    find the user. If the user exist, respond with a 200
    HTTP status and the following JSON payload:
    {"email": "<user email>"}
    """
    session_id = request.cookies.get("session_id", None)
    user = AUTH.get_user_from_session_id(session_id)
    if session_id is None or user is None:
        abort(403)

    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'])
def reset_password() -> str:
    """
    If the email is not registered, respond with a 403 status code.
    Otherwise, generate a token and respond with a 200 HTTP status
    and the following JSON payload:
    {"email": "<user email>", "reset_token": "<reset token>"}

    """
    try:
        email = request.form['email']
    except KeyError:
        abort(403)
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'])
def update_password() -> str:
    """
    Update the password. If the token is invalid, catch the exception
    and respond with a 403 HTTP code. If the token is valid, respond
    with a 200 HTTP code and the following JSON payload:
    {"email": "<user email>", "message": "Password updated"}

    """
    try:
        email = request.form['email']
        reset_token = request.form['reset_token']
        new_password = request.form['new_password']
    except KeyError:
        abort(400)

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
