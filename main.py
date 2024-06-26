#!/usr/bin/env python
"""
A simple app to create a JWT token.
"""
import os
import logging
import datetime
import functools
import jwt

from flask import Flask, jsonify, request, abort

JWT_SECRET = os.environ.get('JWT_SECRET', 'abc123abc1234')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')


def setup_logger():
    '''
    Setup logger format, level, and handler.

    RETURNS: log object
    '''
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log = logging.getLogger(__name__)
    log.setLevel(LOG_LEVEL)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    log.addHandler(stream_handler)
    return log


LOG = setup_logger()
LOG.debug("Starting with log level: %s" % LOG_LEVEL)
APP = Flask(__name__)


def require_jwt(function):
    """
    Decorator to check valid jwt is present.
    """

    @functools.wraps(function)
    def decorated_function(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)
        token = request.headers.get('Authorization').split()[1]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            abort(401, description="Token has expired")
        except jwt.InvalidTokenError:
            abort(401, description="Invalid token")

        return function(*args, **kwargs)

    return decorated_function


@APP.route('/', methods=['GET'])
def health():
    return jsonify("Healthy")


@APP.route('/auth', methods=['POST'])
def auth():
    """
    Create JWT token based on email.
    """
    request_data = request.get_json()
    email = request_data.get('email')
    password = request_data.get('password')
    if not email or not password:
        LOG.error("Missing email or password")
        return jsonify({"message": "Missing email or password"}), 400

    user_data = {'email': email, 'password': password}
    return jsonify(token=_get_jwt(user_data))


@APP.route('/contents', methods=['GET'])
@require_jwt
def decode_jwt():
    """
    Check user token and return non-secret data
    """
    token = request.headers.get('Authorization').split()[1]
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        abort(401, description="Token has expired")
    except jwt.InvalidTokenError:
        abort(401, description="Invalid token")

    response = {'email': data['email'],
                'exp': data['exp'],
                'nbf': data['nbf']}
    return jsonify(response)


def _get_jwt(user_data):
    exp_time = datetime.datetime.utcnow() + datetime.timedelta(weeks=2)
    payload = {
        'exp': exp_time,
        'nbf': datetime.datetime.utcnow(),
        'email': user_data['email']
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


if __name__ == '__main__':
    APP.run(host='127.0.0.1', port=8080, debug=True)
