from flask_login import current_user
from flask_wtf import Form
from wtforms import StringField, TextAreaField, SubmitField, BooleanField, SelectField
from wtforms.validators import Length, DataRequired, Regexp, ValidationError, Email
from flask_pagedown.fields import PageDownField
from .views import User
from ..models import Role


class EditProfileForm(Form):
    username = StringField('Username', validators=[
                DataRequired(),
                Length(1, 64),
                Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                       'username must have only letters, numbers, dots or underscores')
            ])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About Me')
    submit = SubmitField('Save')

    def validate_username(self, field):
        """ validate username to avoid get a username has been used """
        if  current_user.username != field.data and User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already registered.')


class EditProfileAdminForm(Form):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[
        DataRequired(),
        Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'username must have only letters, numbers, dots or underscores')
    ])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About Me')
    submit = SubmitField('Save')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    """
    自定义验证函数。
    如果表单类种定义了以validate_开头且后面跟着表单字段名（比如email）的方法，
    这个方法就和常规的验证函数一起调用。传入的参数是一个字段
    """
    def validate_email(self, field):
        """ validate email to avoid get a email has been used """
        if field.data != self.user.email and  User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')


    def validate_username(self, field):
        """ validate username to avoid get a username has been used """
        if field.data != self.username and User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already registered.')


class PostForm(Form):
    title = StringField('Title', validators=[DataRequired()])
    # body = TextAreaField("What's on your mind?", validators=[DataRequired])
    # support markdown
    body = PageDownField("What' s on your mind?", validators=[DataRequired()])
    submit = SubmitField('Submit')


class CommentForm(Form):
    body = StringField('', validators=[DataRequired()])
    submit = SubmitField('Submit')
