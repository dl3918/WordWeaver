# WordWeaver
Final Project CS178

## To use:
- First, initialize a virtual environment (venv)
```
python3 -m venv .venv
source .venv/bin/activate
```

- Install Ginza, spacy, flask, flask_sqlalchemy

```
python3 -m pip install ginza
python3 -m pip install spacy
```

Install Japanese Dictionary (JAMDICT, using JMdict, KanjiDic2, JMnedict)
- Only run the app.py within the virtual environment, or else ginza will not be recognized.
```
python3 -m pip install wheel jamdict jamdict-data
```
