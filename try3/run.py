import os

from flask import Flask, app
from flask_jwt_extended import JWTManager

from api.database.database import db
from api.conf.config import (
    SQLALCHEMY_DATABASE_URI,
    JWT_SECRET_KEY,
    SECRET_KEY,
    JWT_BLACKLIST_TOKEN_CHECKS
)
from api.conf.routes import generate_routes
from api.models import models

def create_app():
    app = Flask(__name__)

    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config['SQL_ALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = JWT_BLACKLIST_TOKEN_CHECKS
    app.config['JWT_BLACKLIST_TOKEN_ENABLED'] = True

    db.init_app(app)
    jwt = JWTManager(app)

    # @jwt.token_in_blacklist_loader
    # def check_if_token_in_blacklist(decrypted_token):
    #     jti = decrypted_token['jti']

    #     return

    if not os.path.exists(SQLALCHEMY_DATABASE_URI):
        db.app = app
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    db.create_all()
    generate_routes(app)

    app.run()