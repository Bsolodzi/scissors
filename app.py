from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user, login_required
import os
# from utils.models import db

from datetime import datetime

base_dir = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + os.path.join(base_dir,'models.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = '4d4c18d8d33c8c704705'

db = SQLAlchemy(app)
login_manager = LoginManager(app)

@app.before_first_request
def create_tables():
    db.create_all()

class User (db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    first_name = db.Column(db.String(50), nullable =False)
    last_name = db.Column(db.String(50), nullable =False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash =  db.Column(db.Text(), nullable=False)
    links = db.relationship('Link')

    def __repr__(self):
        return f'User<{self.username}>'

class Link (db.Model):
    __tablename__ = "links"
    id = db.Column(db.Integer(), primary_key=True)
    long_link = db.Column(db.String(), nullable =False)
    short_link = db.Column(db.String())
    user = db.Column(db.Integer(), db.ForeignKey('users.id'))

    def __repr__(self):
        return f'User<{self.id}>'


@app.route("/")
def index():
    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)