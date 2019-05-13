from flask_restful import Resource, reqparse
from flask_jwt_extended import (create_access_token,
								create_refresh_token,
								jwt_manager,
								jwt_required,
								jwt_refresh_token_required,
								get_jwt_identity,
								get_raw_jwt)

from api.models.models import UserModel, RevokedTokenModel
from api.error import error

parser = reqparse.RequestParser()


class UserRegister(Resource):
	def post(self):
		parser.add_argument('username', help='Username can not be none', required=True)
		parser.add_argument('password', help='Password can not be none', required=True)
		parser.add_argument('age', help='Age must be integer', type=int)

		data = parser.parse_args()
		print(data)

		if UserModel.find_by_username(data['username']):
			return error.ALREADY_EXIST

		new_user = UserModel(
			username = data['username'],
			password = UserModel.hash_pass(data['password']),
			age = data['age']
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
		except:
			return error.SERVER_ERROR_500


class Login(Resource):
	def post(self):
		parser.add_argument('username', help='Username can not be none', required=True)
		parser.add_argument('password', help='Password can not be none', required=True)

		data = parser.parse_args()

		user = UserModel.find_by_username(data['username'])

		if not user:
			return error.DOES_NOT_EXIST

		if UserModel.check_pass(data['password'], user.password):
			access_token = create_access_token(identity=data['username'])
			refresh_token = create_refresh_token(identity=data['username'])

			return {
				'message': 'Login success',
				'access_token': access_token,
				'refresh_token': refresh_token
			}
		else:
			return error.INVALID_INPUT_422


class Info(Resource):
	@jwt_required
	def get(self):
		user = get_jwt_identity()
		return UserModel.get_one(user)

	@jwt_required
	def patch(self):
		parser.add_argument('age', help='Age must be integer', type=int)
		data = parser.parse_args()
		user = get_jwt_identity()

		if UserModel.update(user, data):
			return UserModel.get_one(user)
		else:
			return error.SERVER_ERROR_500
		# return UserModel.update(user, data)


class TokenRefresh(Resource):
	@jwt_refresh_token_required
	def post(self):
		user = get_jwt_identity()
		access_token = create_access_token(identity=user)

		return {
			'access_token': access_token
		}


class UserLogout(Resource):
	@jwt_required
	def post(self):
		jti = get_raw_jwt()['jti']

		try:
			revoked_token = RevokedTokenModel(jti=jti)
			revoked_token.add()

			return {'message': 'Token has been revoked'}
		except:
			return error.SERVER_ERROR_500


class Index(Resource):
	@jwt_required
	def get(self):
		return {'message': 'Hello world'}