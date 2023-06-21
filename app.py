from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user, login_required
import os
# from utils.models import db

from datetime import datetime

base_dir = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + \
    os.path.join(base_dir, 'models.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = '4d4c18d8d33c8c704705'
app.secret_key = 'sdfjsdfjdwjsjkr4w45ewsfwefwe'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    # Code to retrieve the user object based on the user ID
    return User.query.get(int(user_id))


@app.before_first_request
def create_tables():
    db.create_all()


class User (db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.Text(), nullable=False)
    links = db.relationship('Link')

    def __repr__(self):
        return f'User<{self.username}>'


class Link (db.Model):
    __tablename__ = "links"
    id = db.Column(db.Integer(), primary_key=True)
    long_link = db.Column(db.String(), nullable=False)
    short_link = db.Column(db.String())
    user = db.Column(db.Integer(), db.ForeignKey('users.id'))

    def __repr__(self):
        return f'User<{self.id}>'


@app.route("/")
def index():
    return render_template('login.html')


@app.route('/auth', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('firstname')
        last_name = request.form.get('lastname')
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()
        if password != password2 or len(password) < 6:
            print('Password error')
        elif user:
            print('User already exists')
        if user:
            print('User already exists')
        else:
            user = User(username=username, email=email, first_name=first_name, last_name=last_name,
                        password_hash=generate_password_hash(password, method='sha256'))
            db.session.add(user)
            db.session.commit()
            return render_template('index.html')
    return render_template('landing.html')


@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password_hash, password):
                login_user(user, remember=True)
                return redirect(url_for('home'))
            else:
                print('Incorrect password or username')
        else:
            print('Incorrect password or username')
    return render_template('login.html')


@app.route('/auth/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/home')
def home():
    return render_template('suc_test.html')


if __name__ == "__main__":
    app.run(debug=True)
