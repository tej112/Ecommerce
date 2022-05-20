from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, Email

from sendmail import send_mail

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret'
db = SQLAlchemy(app)

# Login Manager Initialization
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[Length(min=2, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=80)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[InputRequired(), Length(min=4, max=80), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=80)])
    submit = SubmitField('Login')


# Routes
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Home Page
@app.route('/')
def index():
    return render_template('index.html')


# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                if check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid Email-ID or password', 'danger')
                    return redirect(url_for('login'))
            else:
                flash('Invalid Email-ID or password', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Invalid Email-ID or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', form=form)


# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        if form.username.data == "":
            form.username.data = form.email.data.split('@')[0]
        if form.validate_on_submit():
            if form.password.data != form.confirm_password.data:
                flash('Passwords do not match', 'warning')
                return redirect(url_for('register'))
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already exists', 'info')
                return redirect(url_for('register'))
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already exists', 'info')
                return redirect(url_for('register'))

            # noinspection PyArgumentList
            user = User(username=form.username.data, email=form.email.data,
                        password=generate_password_hash(form.password.data, method='pbkdf2:sha256',
                                                        salt_length=8))
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html', form=form)


# Dashboard Page
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('reset_password.html', OTP_ENABLED=False)

    if request.method == "POST":
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        user = User.query.filter_by(email=request.form['email']).first()
        if user and request.form['OTP_ENABLED'] == 'True':
            OTP = send_mail(mail=False, email=user.email)
            if OTP == request.form['otp']:
                user.password = generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
                db.session.commit()
                flash('Password reset successful', "success")
                return redirect(url_for('login'))
            else:
                flash('Invalid OTP', "danger")
                return redirect(url_for('reset_password'))
        if user and request.form['OTP_ENABLED'] == 'Hello':
            send_mail(mail=True, email=user.email)
            return render_template('reset_password.html', OTP_ENABLED=True, email=user.email)


# Logout Page
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# Run Server
if __name__ == '__main__':
    # db.create_all()
    # db.session.commit()
    app.run(debug=True)
