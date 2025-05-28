import os
import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Paths for saving model and vectorizer
MODEL_PATH = "spam_model.pkl"
VEC_PATH = "vectorizer.pkl"

# Train model only if not already saved
def train_and_save_model():
    print("Training spam classifier...")

    # Load SMS Spam Collection dataset
    url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
    df = pd.read_csv(url, sep="\t", names=["label", "message"])
    df['label'] = df['label'].map({'ham': 0, 'spam': 1})

    # Train-test split
    X_train, _, y_train, _ = train_test_split(df['message'], df['label'], test_size=0.2, random_state=42)

    # TF-IDF + Logistic Regression
    vectorizer = TfidfVectorizer(stop_words='english', max_df=0.9)
    X_train_vec = vectorizer.fit_transform(X_train)
    model = LogisticRegression()
    model.fit(X_train_vec, y_train)

    # Save model and vectorizer
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VEC_PATH)
    print("Model and vectorizer saved.")

# Load model/vectorizer or train if missing
if not (os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH)):
    train_and_save_model()

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VEC_PATH)

def is_weird_sentence(text, threshold=0.7):
    """
    Returns True if the text is predicted to be spam-like.
    """
    X = vectorizer.transform([text])
    prob = model.predict_proba(X)[0][1]
    return prob > threshold

def get_spam_probability(text):
    """
    Returns spam probability (0 to 1).
    """
    X = vectorizer.transform([text])
    return round(model.predict_proba(X)[0][1], 4)

# Test block
if __name__ == "__main__":
    test_msg = "Congratulations! You've won a free ticket. Text WIN to 12345."
    print("Message:", test_msg)
    print("Spam probability:", get_spam_probability(test_msg))
    print("Is weird (spam-like)?", is_weird_sentence(test_msg))
