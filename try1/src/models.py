import bcrypt

from run import db

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer, nullable=True, default=0)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

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
    def delete_all(cls):
        try:
            rows = db.session.query(cls).delete()
            db.session.commit()
            return {'message': 'Delete successfully'}
        except:
            return {'message': 'Error'}