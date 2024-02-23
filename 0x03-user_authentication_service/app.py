#!/usr/bin/env python3
"""
Flask app
"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

app = Flask(__name__)
auth = Auth()


@app.route('/', strict_slashes=False)
def home() -> str:
    """
    returns a JSON payload 
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def register_user() -> str:
    """
    Register a new user
    """
    try:
        email = request.form['email']
        pswd = request.form['password']
    except KeyError:
        abort(400)

    try:
        user = auth.register_user(email, pswd)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """
    login a  user using email and password
    """
    try:
        email = request.form['email']
        pswd = request.form['password']
    except KeyError:
        abort(400)
    if not auth.valid_login(email, pswd):
        abort(401)

    msg = {"email": email, "message": "logged in"}
    json_msg = jsonify(msg)
    session_id = auth.create_session(email)
    json_msg.set_cookie("session_id", session_id)
    return json_msg


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """
    logout the user, and redirect to /
    """
    session_id = request.cookies.get("session_id", None)
    user = auth.get_user_from_session_id(session_id)

    if user is None:
        abort(403)
    auth.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """
    find the user. If the user exist, respond with a 200
    HTTP status and the following JSON payload:
    {"email": "<user email>"}
    """
    session_id = request.cookies.get("session_id", None)

    user = auth.get_user_from_session_id(session_id)
    if user is None:
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
        reset_token = auth.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
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
        new_pswd = request.form['new_password']
    except KeyError:
        abort(400)

    try:
        auth.update_password(reset_token, new_pswd)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
