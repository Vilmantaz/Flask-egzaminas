from tkinter import SEPARATOR
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user, logout_user, login_user, login_required, UserMixin
import os
from flask_bcrypt import Bcrypt
import forms

app = Flask(__name__)
app.config['SECRET_KEY'] = '8cb2c6d461bed47503d7162f4638dfbe7e4365d8209e5b8c'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

from sqlalchemy import MetaData
convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}
metadata = MetaData(naming_convention=convention)


basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'data.sqlite')
db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db, render_as_batch=True)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

association_table = db.Table('association', db.metadata,
    db.Column('Groups_id', db.Integer, db.ForeignKey('Groups.id'), primary_key=True),
    db.Column('Users_id', db.Integer, db.ForeignKey('Users.id'), primary_key=True)
)

class Groups(db.Model):
    __tablename__ = 'Groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column('Pavadinimas', db.String(100), unique=True, nullable=False)
    bills = db.relationship('Bills', back_populates='group')
    users = db.relationship('User',  secondary=association_table, back_populates='groups')

class User(db.Model, UserMixin):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column('Vardas ir pavardė', db.String(30), unique=True, nullable=False)
    email = db.Column('El. pašto adresas', db.String(120), unique=True, nullable=False)
    password = db.Column('Slaptažodis', db.String(60),unique=True, nullable=False)
    groups = db.relationship('Groups', secondary=association_table, back_populates='users')
    

class Bills(db.Model):
    __tablename__ = 'Bills'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.String, db.ForeignKey('Groups.id'))
    user_full_name = db.Column(db.String, db.ForeignKey('Users.id'))
    description = db.Column('Apibūdinimas', db.String(50), nullable=False)
    amount = db.Column('Suma', db.Integer, nullable=False)
    user = db.relationship('User')
    group = db.relationship('Groups', back_populates='bills')


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('groups'))
    form = forms.LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(
            email=form.email.data).one()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            flash('Sėkmingai prisijungėte!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('login'))
        else:
            flash('Prisijungti nepavyko. Patikrinkite el. paštą ir slaptažodį', 'danger')
    return render_template('login.html', form=form)

@app.route('/atsijungti')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/registracija', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    form = forms.RegisterForm()
    if form.validate_on_submit():
        coded_password = bcrypt.generate_password_hash(
                form.password.data).decode('utf-8')
        user = User(
            full_name=form.full_name.data, email=form.email.data, password=coded_password)
        db.session.add(user)
        db.session.commit()
        flash('Sėkmingai prisiregistravote! Galite prisijungti', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/grupės', methods=['GET', 'POST'])
def groups():
    form = forms.GroupForm()
    
    try:
        groups = Groups.query.all()
    except:
        abort(404)
    if form.validate_on_submit():
        group = form.group.data
        print (current_user.full_name)
        
        if current_user not in group.users:
            selected_group = Groups.query.get(group.id)
            user = User.query.get(current_user.id)
            selected_group.users.append(user)
            db.session.commit()
        else:
            return 'this user is already in this Group'
        return redirect(url_for('current_group', group_id=group.id))

    return render_template('groups.html', groups=groups, form=form)


@app.route('/grupės/<int:group_id>', methods=['GET', 'POST'])
@login_required
def current_group(group_id):
    group = Groups.query.get(group_id)
    if group is None:
        abort(404)
    bills = Bills.query.all()
    all_groups = Groups.query.all()
    form = forms.BillsForm()
    users = User.query.all()
    form.user_id.choices = [(u.id, u.full_name) for u in group.users]
    print(type(form.user_id.choices))
    
    for user in users:
        if user in group.users:
            if form.validate_on_submit():
                bill = Bills(group_id=group.id, user_full_name=form.user_id.data, description=form.description.data, amount=form.amount.data)
                db.session.add(bill)
                db.session.commit()
                return redirect(url_for('current_group', group_id=group.id))
    return render_template('bills.html', form=form, group=group, all_groups=all_groups, users=users, bills=bills)

@app.route('/grupės/<int:group_id>/<int:bill_id>', methods=['POST'])
def bill_delete(group_id, bill_id):
    group = Groups.query.get(group_id)
    if group is None:
        abort(404)
    record = Bills.query.get(bill_id)
    if record is None:
        abort(404)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for('current_group', group_id=group.id ))


@app.route('/new_group', methods=['GET', 'POST'])
@login_required
def new_group():
    db.create_all()
    form = forms.NewGroupForm()
    if form.validate_on_submit():
        new_group = Groups(name=form.name.data)
        for user in form.users.data:
            assigned_user = User.query.get(user.id)
            new_group.users.append(assigned_user)
        db.session.add(new_group)
        db.session.commit()
        return redirect(url_for('groups'))
    return render_template('groups_form.html', form=form)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
