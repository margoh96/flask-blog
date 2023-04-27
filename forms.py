from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, IntegerField
from wtforms.validators import DataRequired, URL, EqualTo, Length, Regexp
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterUserForm(FlaskForm):
    email = EmailField("Enter Your Email", validators=[DataRequired()])
    password = PasswordField("Enter Your Password", validators=[DataRequired(),
                                                                EqualTo('confirm', message='Passwords must match'),
                                                                Length(min=8, message="Password must be at least 8 characters"),
                                                                Regexp(r'^(?=.*?[A-Z])(?=.*?[^\w\s])', message="Password must contain at least one uppercase letter and one symbol")
                                                                ])
    confirm = PasswordField('Repeat Password', validators=[DataRequired()])
    name = StringField("Enter Your Name", validators=[DataRequired()])
    submit = SubmitField("Create New User")

class LoginUserForm(FlaskForm):
    email = EmailField("Enter Your Email", validators=[DataRequired()])
    password = PasswordField("Enter Your Password", validators=[DataRequired(),
                                                                Length(min=8,
                                                                       message="Password must be at least 8 characters"),
                                                                Regexp(r'^(?=.*?[A-Z])(?=.*?[^\w\s])',
                                                                       message="Password must contain at least one uppercase letter and one symbol")
                                                                ])
    submit = SubmitField("Login")

class CommentForm(FlaskForm):
    # blog_id = IntegerField("Blog ID", validators=[DataRequired()])
    comment = CKEditorField("Comment")
    submit = SubmitField("Send Comment")