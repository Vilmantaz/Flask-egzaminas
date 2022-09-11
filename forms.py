from flask_wtf import FlaskForm
from wtforms_sqlalchemy.fields import QuerySelectField, QuerySelectMultipleField
from wtforms import StringField, SubmitField, PasswordField, BooleanField, TextAreaField, IntegerField, SelectField
from wtforms.validators import DataRequired, ValidationError, EqualTo, Email
import app


class RegisterForm(FlaskForm):
    full_name = StringField('Vardas ir pavardė', [DataRequired()])
    email = StringField('El. paštas', [DataRequired(), Email()])
    password = PasswordField('Slaptažodis', [DataRequired()])
    repeat_password = PasswordField('Pakartokite slaptažodį', [
                                             EqualTo('password', 'Slaptažodis turi sutapti.')])
    submit = SubmitField('Prisiregistruoti')

    def check_user(self, full_name):
        user = app.User.query.filter_by(
            full_name=full_name.data).one()
        if user:
            raise ValidationError('Šis vardas panaudotas. Pasirinkite kitą.')

    def tikrinti_pasta(self, email):
        user = app.User.query.filter_by(
            email=email.data).one()
        if user:
            raise ValidationError(
                'Šis el. pašto adresas panaudotas. Pasirinkite kitą.')

class LoginForm(FlaskForm):
    email = StringField('El. paštas', [DataRequired()])
    password = PasswordField('Slaptažodis', [DataRequired()])
    remember_me = BooleanField('Prisiminti mane')
    submit = SubmitField('Prisijungti')

def group_query():
    return app.Groups.query

def user_query():
    return app.User.query 


class GroupForm(FlaskForm):
    group = QuerySelectField(query_factory=group_query, get_label='id', get_pk=lambda obj: obj.id)
    submit = SubmitField('Pasirinkti')

class NewGroupForm(FlaskForm):
    name = StringField('Pavadinimas', [DataRequired()])
    users = QuerySelectMultipleField(query_factory=user_query, get_label='full_name', get_pk=lambda obj: obj.id)
    submit = SubmitField('Sukurti')

class BillsForm(FlaskForm):
    user_full_name = SelectField(u'User')
    amount = IntegerField('Suma', [DataRequired()])
    description = TextAreaField('Apibūdinimas', [DataRequired()])
    submit = SubmitField('Pateikti')
