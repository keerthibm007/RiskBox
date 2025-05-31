import sys
import os
from flask import Flask, request, jsonify
from datetime import datetime
from googleapiclient.discovery import build

# Fix for module imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Correct imports
from app.gmail_client import authenticate_gmail, fetch_messages, get_email_content, move_email
from app.scanners.attachment_scanner import scan_email, train_attachment_fraud_model

app = Flask(__name__)
@app.route("/", methods=["GET"])
def home():
    return "RiskBox API is running. Use /scan_emails with POST request to scan emails."

@app.route("/test_post", methods=["POST"])
def test_post():
    data = request.get_json()
    return jsonify({"you_sent": data})

@app.route("/scan_emails", methods=["POST"])
def scan_emails_endpoint():
    try:
        scan_time = datetime.now().strftime("%Y-%m-%d %I:%M %p IST")
        print(f"[{scan_time}] Received request to scan emails")

        data = request.get_json()
        user_id = data.get("userId", "me")
        creds = authenticate_gmail()
        service = build('gmail', 'v1', credentials=creds)
        messages = fetch_messages(service)

        fraud_model, fraud_vectorizer = train_attachment_fraud_model()

        summaries = []
        for msg in messages[:5]:
            msg_id = msg['id']
            score, findings, summary, result = scan_email(service, msg_id, fraud_model, fraud_vectorizer)
            summary['Result'] = result
            summaries.append(summary)

        print(f"[{scan_time}] Successfully scanned {len(summaries)} emails")
        return jsonify(summaries)

    except Exception as e:
        error_time = datetime.now().strftime("%Y-%m-%d %I:%M %p IST")
        print(f"[{error_time}] Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0" ,port=5000)
