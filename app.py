"""
This file contains the main content for the ScheduleKing App, an Alternative 
Scheduling App which tells YOU when you will be meeting, whether you like
it, or not.
"""
import random
import string
from flask import Flask, render_template, redirect, request, session, flash
from flask_sqlalchemy import SQLAlchemy
import os
import json
from datetime import datetime, timedelta


app = Flask(__name__)
app.secret_key = os.urandom(24)

# From Flask Todo App Tutorial
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    meetingid = db.Column(db.String)
    duration = db.Column(db.Integer)
    dates = db.Column(db.String)
    count = db.Column(db.Integer)

# Direct to input page
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if (request.method == 'POST'):
        username = request.form.get("username")
        password = request.form.get("password")
        print(username)
        print(password)
        return redirect('/login')
    else:
        return render_template('login.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=True)