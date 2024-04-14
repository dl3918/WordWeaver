"""
This file contains the main content for the ScheduleKing App, an Alternative 
Scheduling App which tells YOU when you will be meeting, whether you like
it, or not.
"""
import random
import json
import string
from flask import Flask, render_template, redirect, request, session, flash
from sqlalchemy.sql import func
from sqlalchemy.types import LargeBinary
from flask_sqlalchemy import SQLAlchemy
import os
import json
from datetime import datetime, timedelta
import hashlib
import hmac
from typing import Tuple

import spacy
nlp = spacy.load("ja_ginza")
# doc = nlp('銀座でランチをご一緒しましょう。')
# for sent in doc.sents:
#     for token in sent:
#         print(
#             token.i,
#             token.orth_,
#             token.lemma_,
#             token.norm_,
#             token.morph.get("Reading"),
#             token.pos_,
#             token.morph.get("Inflection"),
#             token.tag_,
#             token.dep_,
#             token.head.i,
#         )
#     print('EOS')

app = Flask(__name__)
app.secret_key = b'$q\xd3~\xb8I_\x86\x14\x90\xebu\xf8\xc3e$\x8b\xd5\x12\xe6\x14u\xf4z'

# From Flask Todo App Tutorial
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def hash_new_password(password: str) -> Tuple[bytes, bytes]:
    """
    Hash the provided password with a randomly-generated salt and return the
    salt and hash to store in the database.
    """
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt, pw_hash

def is_correct_password(salt: bytes, pw_hash: bytes, password: str) -> bool:
    """
    Given a previously-stored salt and hash, and a password provided by a user
    trying to log in, check whether the password is correct.
    """
    return hmac.compare_digest(
        pw_hash,
        hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    )

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    email = db.Column(db.String(255, collation='NOCASE'), nullable=False, unique=True)
    email_confirmed_at = db.Column(db.DateTime(), server_default=func.now())
    password = db.Column(db.String(255), nullable=False, server_default='')
    language = db.Column(db.String(255), nullable=False, server_default='cn')
    salt = db.Column(db.LargeBinary(255), nullable=False, server_default='')

with app.app_context():
        db.create_all()
        
# Direct to input page
@app.route('/')
def home():
    if (session.get('user')):
        session['language'] = 'cn'
        return redirect('/read')
    return render_template('home.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if (request.method == 'POST'):
        username = request.form.get("username")
        password = request.form.get("password")
        try:
            user = db.one_or_404(db.select(User).filter_by(username=username))
        except:
            flash("Invalid Username")
            return redirect('/login')
        if (is_correct_password(user.salt, user.password, password)):
            session['user'] = user.username
            session['language'] = user.language
            return redirect('/read')
        else:
            return render_template('login.html', incorrect=True)
    else:
        return render_template('login.html', incorrect=False)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if (request.method != 'POST'):
        return render_template('signup.html')
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        passConf = request.form.get("password_confirmation")
        email = request.form.get("email")
        emailConf = request.form.get("email_confirmation")
        if (password == passConf and email == emailConf):
            salt, hash = hash_new_password(password)
            user = User(username=username, password=hash, email=email, salt=salt)
            db.session.add(user)
            db.session.commit()
            session['user'] = username
            print(session['user'])
            return redirect('/select+language')
        else:
            return redirect("/")

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('user', None)
    session.pop('language', None)
    return redirect('/')

@app.route('/select+language', methods=['GET', 'POST'])
def select_language():
    if (request.method != 'POST'):
        return render_template('select.html')
    else:
        language = request.form.get("language")
        try:
            if session['user']:
                username = session['user']
                user = db.one_or_404(db.select(User).filter_by(username=username))
                user.language = language
        except:
            print()
        session['language'] = language
        db.session.commit()
        return redirect('/read')
    

def spanify(language, text):
    spans = []
    if (language == 'jp'):
        doc = nlp(text)
        for sentence in doc.sents:
            for token in sentence:
                spans.append(token.orth_)
    elif (language == 'cn'):
        for i in text:
            spans += i
    return spans

@app.route('/read')
def read():    
    try: 
        username = session['user']
        user = db.one_or_404(db.select(User).filter_by(username=username))
        language = user.language
    except:
        language = session['language']
        with open('static/texts-' + language + '.json') as f:
            data = json.load(f)
            story = data['texts'][random.randint(0,len(data['texts']) - 1)]
            spans = spanify(language, story['text'])
        return render_template('language-guest.html', language=language, spans=spans)
    with open('static/texts-' + language + '.json') as f:
            data = json.load(f)
            story = data['texts'][random.randint(0,len(data['texts']) - 1)]
            spans = spanify(language, story['text'])
    return render_template('language.html', language=session['language'], spans=spans)

@app.route('/profile')
def profile():
    try:
        username = session['user']
        user = db.one_or_404(db.select(User).filter_by(username=username))
        language = user.language
        starttime = user.email_confirmed_at
        starttime = starttime.strftime("%d %B, %Y")
    except:
        return redirect('/')
    return render_template('profile.html', username=session['user'], language=session['language'], starttime=starttime)
if __name__ == '__main__':
    app.run(debug=True)