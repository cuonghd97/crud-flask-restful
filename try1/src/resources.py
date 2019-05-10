from flask_restful import Resource, reqparse
from flask_jwt_extended import (create_access_token,
                                create_refresh_token,
                                jwt_manager,
                                jwt_refresh_token_required,
                                jwt_required,
                                get_jwt_identity,
                                get_raw_jwt)

from models import UserModel

parser = reqparse.RequestParser()
parser.add_argument('username', help='Username can not be none', required=True)
parser.add_argument('password', help='Password can not be none', required=True)
parser.add_argument('age', type=int, help='Age must be integer')

class UserRegister(Resource):
    def post(self):
        data = parser.parse_args()
        print(data)
        if UserModel.find_user_by_name(username=data['username']):
            return {'message': 'User already exist'}

        new_user = UserModel(
            username=data['username'],
            password=UserModel.hash_pass(data['password']),
            age=data['age']
        )
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'Create successfully',
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except:
            return {'mesage': 'error'}, 500


class Login(Resource):
    def post(self):
        data = parser.parse_args()
        user = UserModel.find_user_by_name(data['username'])

        if not user:
            return {'message': 'User does not exist'}

        if UserModel.check_password(data['password'], user.password):
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])

            return {
                'message': 'Login successfully',
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        else:
            return {'message': 'Wrong password or user name'}


class Info(Resource):
    @jwt_required
    def get(self, id):
        return UserModel.get_one(id)


class AllUsers(Resource):
    @jwt_required
    def get(self):
        return UserModel.get_all()


    @jwt_required
    def delete(self):
        return UserModel.delete_all()


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        user = get_jwt_identity()
        access_token = create_access_token(identity=user)

        return {
            'access_token': access_token
        }