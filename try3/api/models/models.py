import bcrypt
from sqlalchemy import exc

from api.database.database import db


class UserModel(db.Model):
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(
		db.String(120),
		unique=True,
		nullable=False)
	password = db.Column(
		db.String(120),
		nullable=False)
	age = db.Column(db.Integer, nullable=True)

	def save_to_db(self):
		db.session.add(self)
		db.session.commit()

	@classmethod
	def find_by_username(cls, username):
		return cls.query.filter_by(username=username).first()

	@staticmethod
	def hash_pass(password):
		return bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

	@staticmethod
	def check_pass(password, hashed):
		return bcrypt.checkpw(password.encode('utf8'), hashed)