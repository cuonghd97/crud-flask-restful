from flask_restful import Api

from api.handlers.UserHandler import (
    UserRegister
)

def generate_routes(app):
    api = Api(app)

    api.add_resource(UserRegister, '/register')