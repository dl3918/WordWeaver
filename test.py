import spacy
nlp = spacy.load("ja_ginza")
doc = nlp("銀座でランチをご一緒しましょう。")
print(doc)