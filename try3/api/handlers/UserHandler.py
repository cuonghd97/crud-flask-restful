from flask_restful import Resource, reqparse
from flask_jwt_extended import (create_access_token,
                           create_refresh_token,
                           jwt_manager,
                           jwt_required,
                           jwt_refresh_token_required,
                           get_jwt_identity,
                           get_raw_jwt)

from api.models.models import UserModel
import api.error.error as error

parser = reqparse.RequestParser()

class UserRegister(Resource):
    def post(self):
        parser.add_argument(
            'username',
            help='Username can not be none',
            required=True
        )
        parser.add_argument(
            'password',
            help='Password can not be none',
            required='True'
        )
        parser.add_argument(
            'age',
            help='Age must be integer',
            type=int
        )

        data = parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return error.ALREADY_EXISTS

        new_user = UserModel(
            username=data['username'],
            password=UserModel.hash_pass(data['username']),
            age=data['age']
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])

            return {
                'message': 'Register success',
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except Exception as e:
            return error.SERVER_ERROR_500