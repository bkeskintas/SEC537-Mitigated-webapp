from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'(?=.*[a-z])', message="Password must include at least one lowercase letter."),
        Regexp(r'(?=.*[A-Z])', message="Password must include at least one uppercase letter."),
        Regexp(r'(?=.*\d)', message="Password must include at least one digit."),
        Regexp(r'(?=.*[@$!%*?&])', message="Password must include at least one special character.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password', message="Passwords must match.")
    ])
    submit = SubmitField('Register')
