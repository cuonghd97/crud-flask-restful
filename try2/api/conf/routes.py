from flask_restful import Api

from api.handlers.UserHandler import UserRegister, Login, Info, TokenRefresh, UserLogout, Index

def generate_routes(app):
	api = Api(app)

	api.add_resource(UserRegister, '/register')
	api.add_resource(Login, '/login')
	api.add_resource(Info, '/info')
	api.add_resource(TokenRefresh, '/refresh-token')
	api.add_resource(UserLogout, '/logout')
	api.add_resource(Index, '/index')