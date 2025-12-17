"""
Forms for the main blueprint.
"""
from datetime import date
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SelectField, DateField, SubmitField, PasswordField, EmailField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Optional

class SignupForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    username = StringField("Username", validators=[Length(min=3, max=50)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class ProfileForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    username = StringField("Username", validators=[Length(min=3, max=150)])
    submit_profile = SubmitField("Update Profile")

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(min=6)])
    confirm_new_password = PasswordField("Confirm New Password", validators=[DataRequired(), EqualTo("new_password")])
    submit_password = SubmitField("Change Password")

class ProjectForm(FlaskForm):
    name = StringField("Project Name", validators=[DataRequired(), Length(max=150)])
    submit = SubmitField("Save Project")

class DomainForm(FlaskForm):
    domain_name = StringField("Domain Name", validators=[DataRequired(), Length(max=255)])
    project_id = SelectField("Project", coerce=int, validators=[Optional()])
    manual_override = BooleanField("Manual Override")

    # Manual domains will now use this expiry date
    ssl_expiry = DateField("SSL Expiry Date", validators=[Optional()])

    submit = SubmitField("Save Domain")

class DomainFilterForm(FlaskForm):
    project_id = SelectField("Project", coerce=int, validators=[Optional()])
    show_manual = BooleanField("Show Manual Override Only")
    submit = SubmitField("Filter")

class DomainSearchForm(FlaskForm):
    search_query = StringField("Search Domain", validators=[Optional(), Length(max=255)])
    submit = SubmitField("Search")
    