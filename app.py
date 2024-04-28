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


class Vocabulary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chinese_word = db.Column(db.String(100), nullable=False)
    translation = db.Column(db.String(100), server_default='')
    pronunciation = db.Column(db.String(100), server_default='')
    level = db.Column(db.String(50), nullable=False)  # Values: 'new', 'familiar', 'confident'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    user = db.relationship('User', back_populates='vocabularies')

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
            return redirect('/select+language')
        else:
            return redirect("/")

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('user', None)
    session.pop('language', None)
    session.pop('story', None)
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
        id = 0
        for sentence in doc.sents:
            for token in sentence:
                if (token.orth_ in ['る', 'て', 'う', 'つ', 'す', 'む', 'ぬ', 'ぶ']):
                    spans[len(spans) - 1]['orth'] += token.orth_
                else:
                    spans.append({'id' : id, 'orth' : token.orth_, 'lemma' : token.lemma_})
                    id += 1
    elif (language == 'cn'):
        id = 0
        for i in text:
            spans.append({'id': id, 'orth' : i})
            id += 1
    return spans

@app.route('/read', methods=['GET', 'POST'])
def read():    
    if (request.method == 'POST'):
        word = request.form.get('word').replace(' ', '')
        dictInfo = dictLookUp(word)
        if session['language'] == 'jp':
            # if 'user' not in session:
            #     return redirect('/login')
            user_id = User.query.filter_by(username=session['user']).first().id

            # Define initial vocabulary
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
        with open('static/texts-' + session['language'] + '.json') as f:
            data = json.load(f)
            story_no = session['story']
            story = data['texts'][story_no]
            spans = spanify(session['language'], story['text'])
            eng_spans = data['texts'][story_no]["en-text"]
        if (session['language'] == "jp"): # Temporary Fix to allow for comparison between Japanese and Chinese Versions
            return render_template('language.html', language=session['language'], spans=spans, eng_spans=eng_spans)
        else:
            return render_template('language.html', language=session['language'], spans=story['text'], eng_spans=eng_spans)
    else:
        try: 
            username = session['user']
            user = db.one_or_404(db.select(User).filter_by(username=username))
            language = user.language
        except:
            language = session['language']
        with open('static/texts-' + language + '.json') as f:
            data = json.load(f)
            story_no = random.randint(0, len(data['texts']) - 1)
            session['story'] = story_no
            story = data['texts'][story_no]
            spans = spanify(language, story['text'])
            eng_spans = data['texts'][story_no]['en-text'] 
            if (session['language'] == "jp"):       
                try:
                    username
                except:
                    return render_template('language-guest.html', language=language, spans=spans)
                return render_template('language.html', language=language, spans=spans, eng_spans=eng_spans)
            else:
                try:
                    username
                except:
                    return render_template('language-guest.html', language=language, spans=story['text'])
                return render_template('language.html', language=language, spans=story['text'], eng_spans=eng_spans)

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


# @app.route('/vocab', methods=['GET', 'POST'])
# def vocab():
#     if (request.method == "POST"):
#         if request.form.get('delete'):
#             delete = request.form.get('delete')
#             user = User.query.filter_by(username=session['user']).first()
#             Vocabulary.query.filter_by(user_id=user.id, chinese_word=delete).delete()
#             db.session.commit()
#             return redirect('/vocab')
#         else:
#             return redirect('/vocab')
#     else:
#         if 'user' not in session:
#             return redirect('/login')
#         user_id = User.query.filter_by(username=session['user']).first().id
#         vocab_list = Vocabulary.query.filter_by(user_id=user_id).all()
#         vocab_dict = {'new': [], 'familiar': [], 'confident': []}
#         for vocab in vocab_list:
#             vocab_dict[vocab.level].append({'word' : vocab.chinese_word, 'sense' : vocab.translation.split('(')[0], 'pronunciation' : vocab.pronunciation})
#         return render_template('vocab.html', vocab=vocab_dict)
@app.route('/vocab', methods=['GET', 'POST'])
def vocab():
    if 'user' not in session:
        return redirect('/login')

    user_id = User.query.filter_by(username=session['user']).first().id

    if request.method == 'POST':
        if request.form.get('delete'):
            # Handle deletion
            delete_word = request.form.get('delete')
            Vocabulary.query.filter_by(user_id=user_id, chinese_word=delete_word).delete()
            db.session.commit()
            return redirect('/vocab')
        elif request.form.get('submit_action') == 'execute_action':
            # Handle story generation
            selected_words = request.form.getlist('selected_words')
            paragraph_type = request.form.get('action') 
            if paragraph_type == 'generate_story':
                selected_type = 'story'
            elif paragraph_type == 'generate_email':
                selected_type = 'email'
            else:
                selected_type = 'newspaper style'
            if not selected_words:
                return "Please select at least one word.", 400

            # Construct the prompt based on selected words and type.
            if selected_words:
                prompt = f"Create a {selected_type} of less than 100 words in Japanese including these words: {', '.join(selected_words)}."
            else:
                prompt = f"Generate a random {selected_type} of less than 100 words in Japanese."

            story, translated_story = generate_story(prompt)  # Assuming generate_story is a function that returns a string
            span = spanify(session['language'], story)
            if story:
                return render_template('language.html', language=session['language'], spans=span, eng_spans=translated_story)
            else:
                return "Failed to generate story due to a network error", 500

    else:
        # GET method for displaying vocab
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
        
        db.session.commit()
        return "Vocabulary seeded successfully!"


from sqlalchemy.orm import sessionmaker
import random
import requests  # Import the requests library
import json
import logging
from openai import OpenAI
from flask import request, jsonify, session, redirect


@app.route('/generate-story', methods=['POST'])
def generate_story(prompt):
    if 'user' not in session:
        return redirect('/login')

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

# @app.route('/generate-story', methods=['GET'])
# def generate_story():
#     if 'user' not in session:
#         return redirect('/login')

#     level = request.args.get('level', default='new')
#     num_words = int(request.args.get('num_words', default=2))

#     user_id = User.query.filter_by(username=session['user']).first().id
#     vocab_list = Vocabulary.query.filter_by(user_id=user_id, level=level).all()

#     if len(vocab_list) < num_words:
#         return "Not enough words in the selected level", 400


#     selected_words = random.sample([vocab.chinese_word for vocab in vocab_list], num_words)
#     prompt = f"请用中文写一段大概100个词的段落，包含以下词汇: {', '.join(selected_words)}."

#     client = OpenAI(api_key="removed for security reason")

#     # Create the chat messages structure for OpenAI API
#     message = [
#         {"role": "system", "content": "You are a helpful assistant."},
#         {"role": "user", "content": prompt}
#     ]

#     try:
#         completion = client.chat.completions.create(
#             model="gpt-3.5-turbo",
#             messages=message
#             )
#         story = completion.choices[0].message.content
#         return jsonify({"story": story}), 200
#     except Exception as e:
#         logging.error(f"OpenAI request failed: {e}")
#         return "Failed to generate story due to a network error."

#     return "An unexpected error occurred."


if __name__ == '__main__':
    app.run(debug=True)