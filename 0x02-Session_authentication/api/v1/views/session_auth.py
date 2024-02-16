#!/usr/bin/env python3
"""
Session Authentication Views Module
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """ POST /auth_session/login
    Return
        - User instance
        - 400 if email or pass are missing
        - 404 if no user found
        - 401 if wrong pass
    """
    email = request.form.get('email')
    if not email:
        return jsonify({"error": "email missing"}), 400
    password = request.form.get('password')
    if not password:
        return jsonify({"error": "password missing"}), 400
    try:
        users_found = User.search({'email': email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404
    if not users_found:
        return jsonify({"error": "no user found for this email"}), 404
    user = users_found[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401
    from api.v1.app import auth
    session_id = auth.create_session(user.id)
    session_name = getenv("SESSION_NAME")
    user_info = jsonify(user.to_json())
    user_info.set_cookie(session_name, session_id)
    return user_info


@app_views.route('/auth_session/logout',
                 methods=['DELETE'], strict_slashes=False)
def logout():
    """ DELETE /auth_session/logout
    Return:
        - empty JSON dictionary with the status code 200
        - 404 if it fails
    """
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
