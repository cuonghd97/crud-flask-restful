import bcrypt

from run import db

from sqlalchemy import exc

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer, nullable=True, default=0)

    def save_to_db(self):
        db.session.add(self)
        try:
            db.session.commit()
        except exc.SQLAlchemyError as er:
            print(er)


    @classmethod
    def find_user_by_name(cls, username):
        return cls.query.filter_by(username=username).first()

    @staticmethod
    def hash_pass(password):
        return bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

    @staticmethod
    def check_password(password, hashed):
        return bcrypt.checkpw(password.encode('utf8'), hashed)

    @classmethod
    def get_all(cls):
        def to_json(item):
            return {
                'id': item.id,
                'username': item.username,
                # 'password': item.password,
                'age': item.age
            }
        # print(UserModel.query.get(1))
        return {'users': list(map(lambda item: to_json(item), UserModel.query.all()))}


    @classmethod
    def get_one(cls, id):
        def to_json(item):
            return {
                'id': item.id,
                'username': item.username,
                'age': item.age
            }
        user = UserModel.query.get(id)
        return {'users': to_json(user)}

    @classmethod
    def update(cls, id, data):
        user = UserModel.query.get(id)
        try:
            user.age = data['age']
            db.session.commit()

            return {'message': 'Success'}
        except exc.SQLAlchemyError as ex:
            print(ex)
            return {'message': 'Error'}

    @classmethod
    def delete_all(cls):
        try:
            rows = db.session.query(cls).delete()
            db.session.commit()
            return {'message': 'Delete successfully'}
        except:
            return {'message': 'Error'}


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