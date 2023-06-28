from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user, login_required
import os
import random
import string

# from utils.models import db

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
    user = db.Column(db.Integer(), db.ForeignKey('users.username'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# class User(UserMixin):
#   def __init__(self, user_id):
#       self.id = user_id


@app.route("/")
def index():
    links = Link.query.all()

    context = {
        'links': links,
    }
    
    return render_template ("index.html", **context)


@app.route('/signup', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm')
        user = User.query.filter_by(email=email).first()
        if password != confirm_password or len(password) < 6:
            flash('Password error')
        elif user:
            flash('User already exists')
        # if user:
        #     flash('User already exists')
        else:
            user = User(username=username, email=email, first_name=first_name, last_name=last_name,
                        password_hash=generate_password_hash(password, method='sha256'))
            db.session.add(user)
            db.session.commit()
            return render_template('login.html')
    return render_template('signup.html')

# to login an already existing user


@app.route('/login', methods=['GET', 'POST'])
def login():

    # check if user has created an account
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()

    # checking if user exists
    if user:

        # checking if the username and the password are the same
        if check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            flash('Incorrect password or username')
    else:
        flash('User does not exist')

    return render_template('login.html')


# generate short link
def generate_short(long_link: str, length=6):
    characters = string.ascii_letters + string.digits
    random_chars = ''.join(random.choice(characters) for _ in range(length))
    return random_chars


@app.route('/short_url')
@login_required
def redirect_to_long_link(short_url):
    long_link = Link.query.filter_by(short_link=short_url).first()
    if long_link:
        return redirect(long_link.long_link)
    flash('Short URL not found.', 'error')
    return redirect(url_for('index'))


# def get_short_link()
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    if request.method == 'POST':
        link = request.form.get('link')
        found_url = Link.query.filter_by(long_link=link).first()
        if found_url:
            return 'URL already exists'
        else:
            short = generate_short(link)
            saved_link = Link(long_link=link, short_link=short,
                              user=current_user.username)
            db.session.add(saved_link)
            db.session.commit()

            # saved_linkk= print(saved_link.short_link)
            
            # return saved_linkk
            # links = Link.query.all()
            # for link in links:
            #     print(link.long_link)
            #     print(link.short_link)
            #     print(link.user)
            # return redirect(url_for('index'))

    return render_template('index.html', links=Link.query.all())


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# route for contact page
@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


# route for deleting a link
@app.route('/delete/<int:id>/', methods=['GET'])
@login_required
def delete(id):
    link_to_delete = Link.query.get_or_404(id)

    db.session.delete(link_to_delete)
    db.session.commit()

    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)