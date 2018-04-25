from application import app, db
from application.models import User, Post, Member, Colleges
from flask import render_template, url_for, redirect, flash, request, make_response
from application.forms import LoginForm, RegistrationForm
from flask_login import logout_user, login_user, current_user
from sklearn.externals import joblib
import pandas as pd
import numpy as np
import re

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

@app.route('/colleges')
def page():
    #if current_user.is_anonymous:
        #return redirect(url_for('login'))

    colleges = Colleges.query.all()

    return render_template('colleges.html', colleges=colleges)


lr3 = joblib.load('application/lr3.pkl')


@app.route('/predict', methods=['GET', 'POST'])
def prediction():

    if request.method == 'POST':
        college = request.form['collegelist']
        cls_rnk = request.form['Class_Rank']
        #hs_type = request.form['HS_Type']
        #hs_state = request.form['HS_State']
        gpa_uw = request.form['GPA_UW']
        gpa_w = request.form['GPA_W']
        sat_m = request.form['SAT_M']
        sat_cr = request.form['SAT_CR']
        sat_w = request.form['SAT_W']
        act = request.form['ACT']
        ea_ed = request.form['EA/ED']
        legacy = request.form['Legacy']
        athlete = request.form['Athlete']


    dict_x = {'UCLA': [0], 'NYU': [0], 'UC_Berkeley': [0], 'Stanford': [0], 'Cornell_U': [0], 'U_Michigan': [0],
              'U_SoCal': [0], 'U_Penn': [0], 'Boston_U': [0], 'UNC_Chapel_Hill': [0], 'Harvard': [0], 'Brown': [0],
              'Duke': [0], 'UCSD': [0], 'UVA': [0], 'UCSB': [0], 'Yale': [0], 'Northwestern': [0], 'Vanderbilt': [0],
              'Princeton': [0], 'U Chicago': [0], 'Northeastern': [0], 'UC_Davis': [0], 'BC': [0], 'Georgetown_U': [0],
              'U_Maryland': [0], 'Georgia_Tech': [0], 'Wash_U': [0], 'MIT': [0], 'Johns_Hopkins': [0], 'NC': [0],
              'CA': [0], 'VA': [0], 'NV': [0], 'NY': [0], 'IL': [0], 'PA': [0], 'NE': [0], 'WA': [0], 'FL': [0], 'CO': [0],
              'GA': [0], 'OR': [0], 'OH': [0], 'DC': [0], 'KS': [0], 'TX': [0], 'NJ': [0], 'IA': [0], 'IN': [0], 'HI': [0],
              'MD': [0], 'MI': [0], 'TN': [0], 'MA': [0], 'AZ': [0], 'AK': [0], 'AR': [0], 'ME': [0], 'CT': [0], 'UT': [0],
              'KY': [0], 'NM': [0], 'MO': [0], 'MN': [0], 'ON': [0], 'OK': [0], 'MT': [0], 'WI': [0], 'LA': [0], 'VT': [0],
              'NH': [0], 'AL': [0], 'SC': [0], 'RI': [0], 'PR': [0], 'ID': [0], 'WV': [0], 'BC': [0], 'VI': [0], 'GU': [0],
              'DE': [0], 'WY': [0], 'MS': [0], 'SD': [0], 'AE': [0], 'AS': [0], 'ND': [0], 'Public': [0], 'Private': [0],
              'Parochial': [0], 'Home': [0], 'GPA_UW': [0], 'GPA_W': [0], 'SAT_M': [0], 'SAT_CR': [0], 'SAT_W': [0],
              'ACT': [0], 'Class_Rank': [0], 'EA/ED': [0], 'Legacy': [0], 'Athlete': [0], 'Year': [2018], 'np.NaN': [0]}

    ca = pd.DataFrame(data=dict_x)

    def convert_college(x):
        if x == 'Boston College':
            ca.loc[:, ('BC')] = 1
        elif x == 'Boston University':
            ca.loc[:, ('Boston U')] = 1
        elif x == 'Brown University':
            ca.loc[:, ('Brown')] = 1
        elif x == 'Cornell University':
            ca.loc[:, ('Cornell U')] = 1
        elif x == 'Duke University':
            ca.loc[:, ('Duke')] = 1
        elif x == 'Georgetown University':
            ca.loc[:, ('Georgetown U')] = 1
        elif x == 'Georgia Institute of Technology':
            ca.loc[:, ('Georgia Tech')] = 1
        elif x == 'Harvard University':
            ca.loc[:, ('Harvard')] = 1
        elif x == 'Johns Hopkins University':
            ca.loc[:, ('Johns Hopkins')] = 1
        elif x == 'Massachusetts Institute of Technology':
            ca.loc[:, ('MIT')] = 1
        elif x == 'New York University':
            ca.loc[:, ('NYU')] = 1
        elif x == 'Northeastern University':
            ca.loc[:, ('Northeastern')] = 1
        elif x == 'Northwestern University':
            ca.loc[:, ('Northwestern')] = 1
        elif x == 'Princeton University':
            ca.loc[:, ('Princeton')] = 1
        elif x == 'Stanford University':
            ca.loc[:, ('Stanford')] = 1
        elif x == 'University of Chicago':
            ca.loc[:, ('U Chicago')] = 1
        elif x == 'University of Maryland':
            ca.loc[:, ('U Maryland')] = 1
        elif x == 'University of Michigan':
            ca.loc[:, ('U Michigan')] = 1
        elif x == 'University of Southern California':
            ca.loc[:, ('U SoCal')] = 1
        elif x == 'University of Pennsylvania':
            ca.loc[:, ('U-Penn')] = 1
        elif x == 'University of California, Berkeley':
            ca.loc[:, ('UC Berkeley')] = 1
        elif x == 'University of California, Davis':
            ca.loc[:, ('UC Davis')] = 1
        elif x == 'University of California, Los Angeles':
            ca.loc[:, ('UCLA')] = 1
        elif x == 'University of California, Santa Barbera':
            ca.loc[:, ('UCSB')] = 1
        elif x == 'University of California, San Diego':
            ca.loc[:, ('UCSD')] = 1
        elif x == 'University of North Carolina, Chapel Hill':
            ca.loc[:, ('UNC Chapel Hill')] = 1
        elif x == 'University of Virginia':
            ca.loc[:, ('UVA')] = 1
        elif x == 'Vanderbilt University':
            ca.loc[:, ('Vanderbilt')] = 1
        elif x == 'Washington University':
            ca.loc[:, ('Wash-U')] = 1
        elif x == 'Yale University':
            ca.loc[:, ('Yale')] = 1
        return ca

    x = convert_college(college)

    print(x)

    ca.loc[:, ('Class_Rank')] = int(cls_rnk)
    #ca['HS_Type'][0] = hs_type
    #ca['HS_State'][0] = hs_state
    ca.loc[:, ('GPA_UW')] = int(gpa_uw)
    ca.loc[:, ('GPA_W')] = int(gpa_w)
    ca.loc[:, ('SAT_M')] = int(sat_m)
    ca.loc[:, ('SAT_CR')] = int(sat_cr)
    ca.loc[:, ('SAT_W')] = int(sat_w)
    ca.loc[:, ('ACT')] = int(act)
    ca.loc[:, ('EA/ED')] = bool(ea_ed)
    ca.loc[:, ('Legacy')] = bool(legacy)
    ca.loc[:, ('Athlete')] = bool(athlete)

    x = ca
    print(x)
    print(type(sat_m))

    prediction = lr3.predict(x)

    if prediction == [0]:
        flash("Yes! You're in!", 'flash')
    else:
        flash("Sorry, you didn't make the cut.", 'flash')

    return render_template('colleges.html')