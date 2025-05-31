import os
import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

MODEL_PATH = "spam_model.pkl"
VEC_PATH = "vectorizer.pkl"

def train_and_save_model():
    print("Training spam classifier...")
    url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
    df = pd.read_csv(url, sep="\t", names=["label", "message"])
    df['label'] = df['label'].map({'ham': 0, 'spam': 1})
    X_train, _, y_train, _ = train_test_split(df['message'], df['label'], test_size=0.2, random_state=42)
    vectorizer = TfidfVectorizer(stop_words='english', max_df=0.9)
    X_train_vec = vectorizer.fit_transform(X_train)
    model = LogisticRegression()
    model.fit(X_train_vec, y_train)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VEC_PATH)
    print("Model and vectorizer saved.")

if not (os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH)):
    train_and_save_model()

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VEC_PATH)

def is_weird_sentence(text, threshold=0.7):
    X = vectorizer.transform([text])
    prob = model.predict_proba(X)[0][1]
    return prob > threshold

def get_spam_probability(text):
    X = vectorizer.transform([text])
    return round(model.predict_proba(X)[0][1], 4)