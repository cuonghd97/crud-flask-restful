from flask_restful import Resource, reqparse
from flask_jwt_extended import (create_access_token,
                                create_refresh_token,
                                jwt_manager,
                                jwt_refresh_token_required,
                                jwt_required,
                                get_jwt_identity,
                                get_raw_jwt)

from models import UserModel, RevokedTokenModel

parser = reqparse.RequestParser()

class UserRegister(Resource):
    def post(self):
        parser.add_argument('username', help='Username can not be none', required=True)
        parser.add_argument('password', help='Password can not be none', required=True)
        parser.add_argument('age', type=int, help='Age must be integer')

        data = parser.parse_args()
        print(data)
        # if UserModel.find_user_by_name(username=data['username']):
        #     return {'message': 'User already exist'}

        new_user = UserModel(
            username=data['username'],
            password=UserModel.hash_pass(data['password']),
            age=data['age']
        )
        print(new_user)
        # new_user.save_to_db()
        access_token = create_access_token(identity=data['username'])
        refresh_token = create_refresh_token(identity=data['username'])
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

        parser.add_argument('username', help='Username can not be none', required=True)
        parser.add_argument('password', help='Password can not be none', required=True)

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

    @jwt_required
    def patch(self, id):
        parser.add_argument('age', type=int, help='Age must be integer')

        data = parser.parse_args()
        return UserModel.update(id, data)


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


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        revoked_token = RevokedTokenModel(jti=jti)
        revoked_token.add()
        return {'message': 'Refresh token has been revoked'}
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Some thing went wrong'}, 500

