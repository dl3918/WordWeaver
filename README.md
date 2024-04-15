# WordWeaver
Final Project CS178

## To use:
- First, create a virtual environment
```
python -m venv .venv
```
- activate the virtual environment (venv)
```
python3 -m venv .venv
source .venv/bin/activate
```

- Install required dependency, e.g., Ginza, spacy, flask, flask_sqlalchemy

```
pip3 install -r requirements.txt
```

Install Japanese Dictionary (JAMDICT, using JMdict, KanjiDic2, JMnedict)
```
python3 -m pip install wheel jamdict jamdict-data
```
- Only run the app.py within the virtual environment, or else ginza will not be recognized.