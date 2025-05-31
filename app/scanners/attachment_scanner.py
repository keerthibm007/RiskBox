import pandas as pd
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from app.gmail_client import get_email_content
from base64 import urlsafe_b64decode
import re
import joblib

# Paths for the dataset and model
DATASET_PATH = os.path.join("spoofing_csv", "enron_data_fraud_labeled.csv")
MODEL_PATH = "attachment_fraud_model.pkl"
VEC_PATH = "attachment_vectorizer.pkl"

def has_attachment(payload):
    """
    Check if the email payload contains an attachment.
    """
    if 'parts' in payload:
        for part in payload['parts']:
            if part.get("filename") and part.get("body", {}).get("attachmentId"):
                return True
    return False

def train_attachment_fraud_model():
    """
    Train a simple fraud detection model based on email body and attachment presence.
    """
    if os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH):
        return joblib.load(MODEL_PATH), joblib.load(VEC_PATH)

    print("Training attachment fraud model...")
    try:
        # Load dataset
        df = pd.read_csv(DATASET_PATH)
        if df.empty:
            raise ValueError("Dataset is empty")

        # Ensure required columns exist
        required_columns = ['body', 'has_attachment', 'is_fraud']
        missing_cols = [col for col in required_columns if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Missing columns in dataset: {missing_cols}")

        # Prepare features: combine body text and attachment presence
        df['has_attachment'] = df['has_attachment'].astype(int)
        df['features'] = df['body'].astype(str) + " " + df['has_attachment'].astype(str)

        # Vectorize text
        vectorizer = TfidfVectorizer()
        X = vectorizer.fit_transform(df['features'])
        y = df['is_fraud'].astype(int)

        # Train model
        model = LogisticRegression()
        model.fit(X, y)

        # Save model and vectorizer
        joblib.dump(model, MODEL_PATH)
        joblib.dump(vectorizer, VEC_PATH)
        print("Attachment fraud model trained and saved.")

        return model, vectorizer
    except Exception as e:
        print(f"Error training attachment fraud model: {str(e)}")
        raise

def predict_fraud(email_body, has_attachment_flag, model, vectorizer):
    """
    Predict if an email is fraudulent based on body and attachment presence.
    """
    try:
        # Combine body and attachment flag
        feature = f"{email_body} {int(has_attachment_flag)}"
        X = vectorizer.transform([feature])
        fraud_prob = model.predict_proba(X)[0][1]  # Probability of being fraudulent
        return round(fraud_prob, 4)
    except Exception as e:
        print(f"Error predicting fraud: {str(e)}")
        return 0.0
    
def scan_email(service, msg_id, model, vectorizer):
    """
    Extracts content and runs fraud prediction on a Gmail message.
    """
    try:
        # Fetch headers and body from Gmail
        message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        payload = message.get('payload', {})
        headers = {h['name']: h['value'] for h in payload.get('headers', [])}
        
        # Extract plain text body
        body = ''
        if 'parts' in payload:
            for part in payload['parts']:
                if part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                    body = urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
        elif 'body' in payload and 'data' in payload['body']:
            body = urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')

        # Determine if the email has an attachment
        attachment_flag = has_attachment(payload)

        # Predict fraud
        fraud_score = predict_fraud(body, attachment_flag, model, vectorizer)
        result = "Malicious" if fraud_score >= 0.5 else "Safe"

        # Extract some links for reporting
        links = re.findall(r'https?://\S+', body)

        summary = {
            "Message ID": msg_id,
            "From": headers.get("From", ""),
            "Subject": headers.get("Subject", ""),
            "Link Count": len(links),
            "Links": links[:5],
            "Attachment Present": bool(attachment_flag),
            "Fraud Score": fraud_score,
            "Result": result
        }

        findings = {
            "Predicted": result,
            "Score": fraud_score,
            "Link Count": len(links)
        }

        return fraud_score, findings, summary, result

    except Exception as e:
        print(f"Error scanning email: {str(e)}")
        raise