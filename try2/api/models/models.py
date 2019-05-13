import bcrypt

from sqlalchemy import exc

from api.database.database import db


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer, nullable=True)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def get_one(cls, username):
        def to_json(item):
            return {
                'id': item.id,
                'username': item.username,
                'age': item.age
            }

        user = cls.query.filter_by(username=username).first()
        return {'user': to_json(user)}

    @classmethod
    def update(cls, username, data):
        user = cls.query.filter_by(username=username).first()
        try:
            user.age = data['age']
            db.session.commit()
            return True
        except exc.SQLAlchemyError as er:
            print(er)
            return False

    @staticmethod
    def hash_pass(password):
        return bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

    @staticmethod
    def check_pass(password, hashed):
        return bcrypt.checkpw(password.encode('utf8'), hashed)

    class RevokedTokenModel(db.Model):
        __tablename__ = 'revoked_token'

        id = db.Column(db.Integer, primary_key=True)
        jti = db.Column(db.String(120))

        def add(self):
            db.session.add(self)
            db.session.commit()

        @classmethod
        def is_jti_blacklisted(cls, jti):
            query = cls.query.filter_by(jti=jti).first()

            return bool(query)
