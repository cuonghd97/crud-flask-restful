import datetime

from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret-key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'
app.config['JWT_BLACKLIST_TOKEN_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=4)

jwt = JWTManager(app)
api = Api(app)
db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()

import views, models, resources

# Route

api.add_resource(resources.UserRegister, '/register')
api.add_resource(resources.Login, '/login')
api.add_resource(resources.Info, '/info/<int:id>')
api.add_resource(resources.AllUsers, '/all-users')
api.add_resource(resources.TokenRefresh, '/refresh-token')

if __name__ == "__main__":
    app.run()