import os

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data.db')
SECRET_KEY = 'secret-key'
JWT_SECRET_KEY = 'jwt-secret-key'
JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']