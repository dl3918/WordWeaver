"""
This file contains the main content for the WordWeaver App, a language  
learning App which helps you learn vocabulary with tailored stories.
"""
import random
import json
import numpy as np
import string
from flask import Flask, render_template, redirect, request, session, flash, jsonify
from sqlalchemy.sql import func
from sqlalchemy.types import LargeBinary
from flask_sqlalchemy import SQLAlchemy
import os
import json
from datetime import datetime, timedelta
import hashlib
import hmac
from typing import Tuple
from jamdict import Jamdict
jam = Jamdict()

import spacy
nlp = spacy.load("ja_ginza")
import openai
import spacy
os.environ['FLASK_ENV'] = 'development'  # Activates development environment, which turns on the debugger and reloader
os.environ['FLASK_DEBUG'] = '1'  # Explicitly enable debug mode

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

def dictLookUp(string):
    result = jam.lookup(string)
    if not result.entries:
        out = result.names
    else:
        out = result.entries
    if out:
        return out[0]
    else: return out

# Relevant concept: user
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    email = db.Column(db.String(255, collation='NOCASE'), nullable=False, unique=True)
    email_confirmed_at = db.Column(db.DateTime(), server_default=func.now())
    password = db.Column(db.String(255), nullable=False, server_default='')
    language = db.Column(db.String(255), nullable=False, server_default='cn')
    salt = db.Column(db.LargeBinary(255), nullable=False, server_default='')
    vocabularies = db.relationship('Vocabulary', back_populates='user', lazy='dynamic') # include a back reference
    stories = db.relationship('Story', back_populates='user')

# Revelant concept: vocabulary
class Vocabulary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chinese_word = db.Column(db.String(100), nullable=False)
    translation = db.Column(db.String(100), server_default='')
    pronunciation = db.Column(db.String(100), server_default='')
    level = db.Column(db.String(50), nullable=False)  # Values: 'new', 'familiar', 'confident'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    seen = db.Column(db.Integer, default=0)
    user = db.relationship('User', back_populates='vocabularies')

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    story = db.Column(db.String(255), nullable=False, unique=True)
    user = db.relationship('User', back_populates='stories')

with app.app_context():
        db.create_all()
        
# Direct to input page
@app.route('/')
def home():
    if (session.get('user')):
        session['language'] = 'cn'
        return redirect('/read')
    return render_template('home.html')

# Relevant concept: user
@app.route('/login', methods=['GET','POST'])
def login():
    if (request.method == 'POST'):
        username = request.form.get("username")
        password = request.form.get("password")
        try:
            user = db.one_or_404(db.select(User).filter_by(username=username))
            print("user found")
        except:
            print("user not found")
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
# Relevant concept: user
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
            session['user'] = username
            db.session.commit()
            return redirect('/select+language')
        else:
            return redirect("/")
# Relevant concept: user
@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('user', None)
    session.pop('language', None)
    session.pop('story', None)
    session.pop('selected_words', None)
    return redirect('/')

# Revelant concept: language
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
        session.pop('language', None)
        session['language'] = language
        db.session.commit()
        return redirect('/read')
    
# Revelant concept: language
def spanify(language, text):
    spans = []
    if (language == 'jp'):
        doc = nlp(text)
        id = 0
        for sentence in doc.sents:
            for token in sentence:
                if (token.orth_ in ['る', 'て', 'う', 'つ', 'す', 'む', 'ぬ', 'ぶ']):
                    spans[len(spans) - 1]['orth'] += token.orth_
                else:
                    spans.append({'id' : id, 'orth' : token.orth_, 'lemma' : token.lemma_})
                    id += 1
    elif (language == 'cn'):
        spans.append({'id': 0, 'orth' : text})
    return spans

@app.route('/read', methods=['GET', 'POST'])
def read():
    if 'user' not in session:
        if 'story' not in session: # Relevant Concept: story
            paragraph_type = session.get('paragraph_type', 'story')
            language = ""
            if session['language'] == 'cn':
                language = "Chinese"
            elif session['language'] == 'jp':
                language = "Japanese"
            else:
                language = "English"
            prompt = f"Generate a random {paragraph_type} of about than 100 words in {language}."
            story, trans = generate_story(prompt)  # Assuming generate_story returns a tuple
        else:
            story = session['story']
        span = spanify(session['language'], story)
        if session['language'] == 'jp':
            for i in span:
                i['sense'] = [j for j in dictLookUp(i['lemma'])]
        session['story'] = story
        return render_template('language-guest.html', spans=span, story=story, language=session['language'])

    user_id = User.query.filter_by(username=session['user']).first().id

    if request.method == 'POST': # Relevant concept: vocabulary
        if 'word' in request.form:
            word = request.form['word'].strip()
            if word:
                dictInfo = dictLookUp(word)

                # Define initial vocabulary
                # Revelant concept: vocabulary
                vocab = []
                for sense in dictInfo.senses:
                    if len(dictInfo.kanji_forms) > 0:
                        vocab.append({'chinese_word': str(dictInfo.kanji_forms[0]), 'level': 'new', 'user_id': user_id, 'translation' : str(sense), 'pronunciation': str(dictInfo.kana_forms[0])})
                    else:
                        vocab.append({'chinese_word': str(dictInfo.kana_forms[0]), 'level': 'new', 'user_id': user_id, 'translation' : str(sense), 'pronunciation': str(dictInfo.kana_forms[0])})
                for vocab_item in vocab:
                    if not Vocabulary.query.filter_by(chinese_word=vocab_item['chinese_word'], user_id=user_id).first():
                        new_vocab = Vocabulary(**vocab_item)
                        db.session.add(new_vocab)
                        db.session.commit()
                        return jsonify({'success': True, 'message': 'Word added successfully'})


        # generate_new_story = request.form.get('generate', False)
        if 'generate' in request.form and request.form['generate'] == 'true':
            new = [i for i in Vocabulary.query.filter(Vocabulary.seen <= 5).filter_by(user_id=user_id)]
            comfortable = [i for i in Vocabulary.query.filter(
                Vocabulary.seen > 5, Vocabulary.seen <= 10
                ).filter_by(user_id=user_id)   ]         
            advanced = [i for i in Vocabulary.query.filter(Vocabulary.seen > 10).filter_by(user_id=user_id)]
            indices = []
            if (len(new) + len(comfortable) + len(advanced)) > 10:
                if len(advanced) >= 1 and len(comfortable) >= 3 and len(new) >= 1:
                    indices = [{'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': comfortable, 'index' : random.randint(0,len(comfortable) - 1)},
                            {'set': comfortable, 'index' : random.randint(0,len(comfortable) - 1)},
                            {'set': comfortable, 'index' : random.randint(0,len(comfortable) - 1)},
                            {'set': advanced, 'index' : random.randint(0,len(advanced) - 1)}]
                elif len(advanced) <= 0 and len(comfortable) >= 3 and len(new) >= 1:
                    indices = [{'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(comfortable) - 1)},
                            {'set': comfortable, 'index' : random.randint(0,len(comfortable) - 1)},
                            {'set': comfortable, 'index' : random.randint(0,len(comfortable) - 1)},
                            {'set': comfortable, 'index' : random.randint(0,len(advanced) - 1)}]
                elif len(advanced) <= 0 and len(comfortable) <= 0 and len(new) >= 1:
                    [{'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(new) - 1)},
                            {'set': new, 'index' : random.randint(0,len(comfortable) - 1)},
                            {'set': new, 'index' : random.randint(0,len(comfortable) - 1)},
                            {'set': new, 'index' : random.randint(0,len(comfortable) - 1)},
                            {'set': new, 'index' : random.randint(0,len(advanced) - 1)}]
            else:
                indices = [{'set': new, 'index' : i} for i in range(len(new))] + [{'set': comfortable, 'index' : i} for i in range(len(comfortable))] + [{'set': advanced, 'index' : i} for i in range(len(advanced))]
            selected_words = session.get('selected_words', [])
            selected_words += [index['set'][index['index']].chinese_word for index in indices]
            paragraph_type = request.form.get('paragraph_type')
            language = ""
            if session['language'] == 'cn':
                language = "Chinese"
            elif session['language'] == 'jp':
                language = "Japanese"
            else:
                language = "English"
            if not selected_words:
                prompt = f"Generate a random {paragraph_type} of about 100 words in {language}."
            else:
                prompt = f"Create a {paragraph_type} of about 100 words in {language} including these words: {', '.join(selected_words)}."

            story, trans = generate_story(prompt)  # Assuming generate_story returns a tuple
            for index in indices:
                if index['set'][index['index']].chinese_word in story:
                    # Relevant concept: vocabulary
                    v = Vocabulary.query.filter_by(chinese_word=index['set'][index['index']].chinese_word).first()
                    v.seen += 1
                    if v.seen > 5 and v.seen <= 10:
                        v.level = "familiar"
                    elif v.seen > 10:
                        v.level = "confident"
                    db.session.commit()
            span = spanify(session['language'], story)
            if session['language'] == 'jp':
                for i in span:
                    i['sense'] = [j for j in dictLookUp(i['lemma'])]
            session['story'] = story
            return render_template('language.html', language=session['language'], spans=span, story=story)
    else:
        # If not POST or no specific action taken, show the language page normally
        if 'story' in session: # Relevant Concept: story
            print(session['story'])
            span = spanify(session['language'], session['story'])
            if session['language'] == 'jp':
                for i in span:
                    if 'lemma' in i:
                        i['sense'] = [j for j in dictLookUp(i['lemma'])]
            return render_template('language.html', language=session['language'], spans=span, story=session['story'])

        else:
            return render_template('language.html')
@app.route('/save', methods=['GET', 'POST'])
def save():
    if 'user' not in session:
        return redirect('/login')

    user_id = User.query.filter_by(username=session['user']).first().id
    language = User.query.filter_by(username=session['user']).first().language
    if request.method == 'POST': # Relevant Concept: story
        story = request.form['save-story']
        if not Story.query.filter_by(story=story, user_id=user_id).first():
            story_entry = Story(story=story, user_id=user_id)
            db.session.add(story_entry)
            message = "Story saved successfully."
            message = "Story sucessfully saved!"
        else:
            message="Story already saved"
        db.session.commit()
        span = spanify(session['language'], story)
        return jsonify({'success': True, 'message': message})
    else:
        return redirect('/read')

# Relevant Concept: story
@app.route('/stories', methods=['GET', 'POST'])
def stories():
    if 'user' not in session:
        return redirect('/login')

    user_id = User.query.filter_by(username=session['user']).first().id
    language = User.query.filter_by(username=session['user']).first().language
    story_query = Story.query.filter_by(user_id=user_id).all()
    if request.method == 'POST': 
        if 'load' in request.form:
            session.pop('story', None)
            session.pop('selected_words', None)
            session['story'] = Story.query.filter_by(id=request.form['load']).first().story
            return redirect('/read')
        elif 'delete' in request.form:
            session.pop('story', None)
            Story.query.filter_by(user_id=user_id, id=request.form['delete']).delete()
            db.session.commit()
            return redirect('/stories')
    else:
        return render_template("stories.html", stories=story_query)

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
    return render_template('profile.html', username=session['user'], language=language, starttime=starttime)


@app.route('/vocab', methods=['GET', 'POST'])
def vocab():
    if 'user' not in session:
        return redirect('/login')

    user_id = User.query.filter_by(username=session['user']).first().id
    # Relevant concept: vocabulary
    if request.method == 'POST':
        if request.form.get('delete'):
            delete_word = request.form.get('delete')
            Vocabulary.query.filter_by(user_id=user_id, chinese_word=delete_word).delete()
            db.session.commit()
            return redirect('/vocab')
        elif request.form.get('submit_action') == 'execute_action':
            selected_words = request.form.getlist('selected_words')
            paragraph_type = request.form.get('action')
            # Save selected words and paragraph type in session for later use
            session['selected_words'] = selected_words
            session['paragraph_type'] = paragraph_type
            flash('Your selection has been saved! Go to "Read" to generate your story.', 'info-selection')
            return redirect('/vocab')

    else:
        vocab_list = Vocabulary.query.filter_by(user_id=user_id).all()
        vocab_dict = {'new': [], 'familiar': [], 'confident': []}
        for vocab in vocab_list:
            vocab_dict[vocab.level].append({'word': vocab.chinese_word, 'sense': vocab.translation.split('(')[0], 'pronunciation': vocab.pronunciation})
        return render_template('vocab.html', vocab=vocab_dict)

@app.route('/seed-vocabulary')
def seed_vocabulary():
    if 'user' not in session:
        return redirect('/login')
    user_id = User.query.filter_by(username=session['user']).first().id

    # Define initial vocabulary
    if (session['language'] == 'cn'):

        initial_vocab = [
            {'chinese_word': '书本', 'level': 'new', 'user_id': user_id},
            {'chinese_word': '洗澡', 'level': 'new', 'user_id': user_id},
            {'chinese_word': '早上', 'level': 'familiar', 'user_id': user_id},
            {'chinese_word': '你好', 'level': 'confident', 'user_id': user_id},
            {'chinese_word': '我', 'level': 'confident', 'user_id': user_id}
        ]

        # Add to database if not already present
        for vocab in initial_vocab:
            if not Vocabulary.query.filter_by(chinese_word=vocab['chinese_word'], user_id=user_id).first():
                new_vocab = Vocabulary(**vocab)
                db.session.add(new_vocab)
            else:
                v = Vocabulary.query.filter_by(chinese_word=vocab['chinese_word'], user_id=user_id).first()
                v.seen = 0
        db.session.commit()
        return "Vocabulary seeded successfully!"


from sqlalchemy.orm import sessionmaker
import random
import requests  # Import the requests library
import json
import logging
from openai import OpenAI
from flask import request, jsonify, session, redirect

# Relevant Concept: story
@app.route('/generate-story', methods=['POST'])
def generate_story(prompt):
    try:
        # client = OpenAI(api_key="")  # Replace with actual API key
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        story = completion.choices[0].message.content

        translation_prompt = f"Translate the following story to English: {story}"
        translation_completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": translation_prompt}
            ]
        )
        translated_story = translation_completion.choices[0].message.content
        # jsonify({"story": story}), 200
        return story, translated_story
    except Exception as e:
        logging.error(f"OpenAI request failed: {e}")
        return "Failed to generate story due to a network error."

    return "An unexpected error occurred."

if __name__ == '__main__':
    app.run(debug=True)