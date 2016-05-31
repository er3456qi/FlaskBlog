from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin, AnonymousUserMixin
from flask import current_app
from . import db
from . import login_manager


class Permission():
    FOLLOW = 0x01  # 关注用户
    COMMENT = 0x02  # 发布评论
    WRITE_ARTICLES = 0x04  # 写文章
    MODERATE_COMMENTS = 0x08  # 删评论
    ADMINISTER = 0x80  # 管理员


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)  # 只有一个角色的default字段要设为False，其他都为True
    permissions = db.Column(db.Integer)
    # backref反向添加了一个名字为role的字段给User.
    # lazy='dynamic' 让数据库动态执行（禁止自动查询），这样users是一个查询而不是查询结果，可以对其添加过滤器
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __str__(self):
        return '<Role {}>'.format(self.name)

    @staticmethod
    def insert_roles():
        """
        此函数并不直接创建新角色，而是通过角色名查找现有角色，然后进行更新。
        只有当数据库中没有某个角色时才创建新的角色对象。
        """
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True), # normal user.for
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False), # assistant manager
            'Administrator': (0xff, False)  # Administrator
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions, role.default = roles[r]
            db.session.add(role)
        db.session.commit()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __str__(self):
        return '<User {}>'.format(self.username)

    def __init__(self, **kwargs):
        """
        User类的构造函数，县调用基类的构造函数，如果创建基类对象后还没定义角色，
        则根据电子邮件地址决定将其设为管理员还是默认角色（普通角色）。
        """
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['BLOG_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
                self.confirmed = True
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    # role confirm
    def can(self, permissions):
        """
        如果角色的权限包括permissions， 则返回True
        """
        return self.role is not None and (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)
    # end role confirm

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

    # account confirm
    confirmed = db.Column(db.Boolean, default=False)

    def generate_confirmation_token(self, expiration=3600):
        """
        # 生成一个令牌，有效期默认是一个小时,
        令牌是个名值对，名字是confirm，值是根据id生成的。
        """
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        """
        确认令牌是否正确。loads出令牌内容，之后解码确认其是否是id值
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True
    # end account confirm


class AnonymousUser(AnonymousUserMixin):
    """
    出于一致性考虑，我们定义了AnonymousUser类，继承自AnonymousUserMixin
    并将其设置为用户未登录时的current_user值。
    这样程序不用先检查用户是否登陆，
    就能自由调用current_user.can()和current_user.is_administrator()方法
    """
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    """
    Login_Manager要求实现的一个回调函数，使用指定的标识符家在用户
    """
    return User.query.get(int(user_id))