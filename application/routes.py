from application import app, db
from application.models import User, Post, Member, Colleges
from flask import render_template, url_for, redirect, flash, request
from application.forms import LoginForm, RegistrationForm
from flask_login import logout_user, login_user, current_user
import pandas as pd
from sklearn.externals import joblib

@app.route("/")
@app.route('/index')
def index():
    posts = Post.query.all()
    member = Member.query.all()
    return render_template('index.html', posts=posts, member=member, title="Welcome!")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        flash('Login requested for user {}; "Remember me" is {}'.format(form.username.data, form.remember_me.data), 'flash')
        user = User.query.filter_by(username=form.username.data).first()

        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'flash')
            return redirect(url_for('login'))

        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return "You have been registered"

    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'flash')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)

lr3 = joblib.load('application/lr3.pkl')

@app.route('/colleges')
def prediction():

    colleges = Colleges.query.all()

    return render_template('colleges.html', colleges=colleges)
