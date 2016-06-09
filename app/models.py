import hashlib
import bleach
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin, AnonymousUserMixin
from flask import current_app, request
from markdown import markdown
from . import db
from . import login_manager


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    following_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)


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


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.now)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),
                                                       tags=allowed_tags, strip=True))


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64), unique=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.now)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    body_html = db.Column(db.Text)

    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),
                                                       tags=allowed_tags, strip=True))

    @staticmethod
    def generate_fake_post(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        titles = set()
        for i in range(count):
            t = forgery_py.lorem_ipsum.sentence()
            while t in titles:
                t = forgery_py.lorem_ipsum.sentence()
            titles.add(t)
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(title=t,
                     body=forgery_py.lorem_ipsum.sentences(randint(1, 3)),
                     timestamp=forgery_py.date.date(True),
                     author=u)
            db.session.add(p)
        db.session.commit()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.now)  # now 不加括号是因为default参数接受函数作为默认值
    last_seen = db.Column(db.DateTime(), default=datetime.now)  # 而这样不加括号，会在初始化时调用，时间是字段生成的时间

    posts = db.relationship('Post', backref='author', lazy='dynamic')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    followers = db.relationship('Follow',
                                foreign_keys=[Follow.following_id],
                                backref=db.backref('following', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan'
                                )
    following = db.relationship('Follow',
                                foreign_keys=[Follow.follower_id],
                                backref=db.backref('follower', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan'
                                )

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, following=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.following.filter_by(following_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        return self.following.filter_by(following_id=user.id).first() is not None

    def is_following_by(self, user):
        return self.followers.filter_by(follower_id=user.id).first() is not None

    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.following_id==Post.author_id).filter(Follow.follower_id==self.id)

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
        db.session.commit()

    @staticmethod
    def generate_fake_user(count=100):
        from random import seed
        import forgery_py

        seed()
        emails, names = set(), set()
        for i in range(count):
            m = forgery_py.internet.email_address()
            while m in emails:
                m = forgery_py.internet.email_address()
            emails.add(m)
            n = forgery_py.internet.user_name()
            while n in names:
                n = forgery_py.internet.user_name()
            names.add(n)
            u = User(email=m,
                     username=n,
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
        db.session.commit()

    def ping(self):
        """
        每次收到用户请求时都要调用ping方法以更新时间。
        """
        self.last_seen = datetime.now()
        db.session.add(self)

    def __str__(self):
        return '<User {}>'.format(self.username)

    avatar_hash = db.Column(db.String(32))

    def gravatar(self, size=100, default='identicon', rating='g'):
        url = 'http://en.gravatar.com/avatar'
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating
        )

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
        if self.email and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()

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

    @property
    def followed_posts(self):
        return None


login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    """
    Login_Manager要求实现的一个回调函数，使用指定的标识符家在用户
    """
    return User.query.get(int(user_id))


"""
on_changed_body 函数注册在body字段上，是SQLAlchemy 'set' 事件的监听程序。
这意味着只要这个类实例的body字段设了新值，函数就会自动被调用。
on_changed_body 把表单的markdown内容抓换成html存到body_html中。
"""
db.event.listen(Post.body, 'set', Post.on_changed_body)