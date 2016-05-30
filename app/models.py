from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db
from . import login_manager


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    # backref反向添加了一个名字为role的字段给User.
    # lazy='dynamic' 让数据库动态执行（禁止自动查询），这样users是一个查询而不是查询结果，可以对其添加过滤器
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __str__(self):
        return '<Role {}>'.format(self.name)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __str__(self):
        return '<User {}>'.format(self.username)

    # password hash
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    # end password hash


@login_manager.user_loader
def load_user(user_id):
    """
    Login_Manager要求实现的一个回调函数，使用指定的标识符家在用户
    """
    return User.query.get(int(user_id))