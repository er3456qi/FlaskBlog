from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from app.models import User

class LoginForm(Form):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(1,64)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class RegistrationForm(Form):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[
        DataRequired(),
        Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'username must have only letters, numbers, dots or underscores')
    ])
    password = PasswordField('Password', validators=[DataRequired(),
                                                     EqualTo('re_password',
                                                             message='Passwords must match')])
    re_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    """
    自定义验证函数。
    如果表单类种定义了以validate_开头且后面跟着表单字段名（比如email）的方法，
    这个方法就和常规的验证函数一起调用。传入的参数是一个字段
    """
    def validate_email(self, field):
        """ validate email to avoid get a email has been used """
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')


    def validate_username(self, field):
        """ validate username to avoid get a username has been used """
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already registered.')