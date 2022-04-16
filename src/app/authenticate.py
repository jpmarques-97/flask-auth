from functools import wraps

import jwt
from flask import request, jsonify, current_app

from app.models import User


def jwt_required(f):

    @wraps(f)
    def wrapper(*args, **kwargs):
        
        token = request.headers.get("authorization")
        print(token)
        if not token:
            message = {
                "error": "permissao negada"
            }
            status = 403
            return jsonify(message), status

        if not "Bearer" in token:
            message = {
                "error": "token invalido"
            }
            status = 401
            return jsonify(message), status

        try:
            token_pure = token.replace("Bearer ", "")
            decoded = jwt.decode(token_pure, current_app.config["SECRET_KEY"])
            current_user = User.query.get(decoded["id"])
        except:
            message = {
                "error": "token invalido"
            }
            status = 403
            return jsonify(message), status

        return f(current_user=current_user, *args, **kwargs)

    return wrapper
