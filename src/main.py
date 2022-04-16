from flask import jsonify, request
from flask_migrate import Migrate

from app import app, db
from app.models import User, user_share_schema, users_share_schema
from app.authenticate import jwt_required

import datetime
import jwt


Migrate(app,db)

@app.shell_context_processor
def make_shell_context():
    return dict(
            app=app,
            db=db,
            User=User)


@app.post("/auth/register")
def register():

    username = request.json["username"]
    email = request.json["email"]
    password = request.json["password"]

    user = User(
        username=username,
        email=email,
        password=password
    )
    db.session.add(user)
    db.session.commit()

    result = user_share_schema.dump(
        User.query.filter_by(email=email).first()
    )

    return jsonify(result) 

@app.post("/auth/login")
def login():

    email = request.json["email"]
    password = request.json["password"]
    
    user = User.query.filter_by(email=email).first_or_404()
    if not user.verify_password(password):
        return jsonify({"error":"credenciais invalidas"}), 403
    
    payload = {
        "id": user.id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"])

    return jsonify({"token":token.decode("utf-8")})

@app.get("/auth/users")
@jwt_required
def users(current_user):

    result = users_share_schema.dump(
        User.query.all()
    )
    return jsonify(result)

@app.get("/auth/current_user")
@jwt_required
def current_user(current_user):

    result = user_share_schema.dump(
        current_user
    )
    return jsonify(result)
