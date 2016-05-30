from . import db


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    # backref反向添加了一个名字为role的字段给User.
    # lazy='dynamic' 让数据库动态执行（禁止自动查询），这样users是一个查询而不是查询结果，可以对其添加过滤器
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __str__(self):
        return '<Role {}>'.format(self.name)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __str__(self):
        return '<User {}>'.format(self.username)
