import base64
import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from app.scanners.spoof_checker import check_spoof
from app.scanners.link_scanner import extract_links, scan_links
from app.scanners.nlp_checker import is_weird_sentence
from app.scanners.attachment_scanner import has_attachment, train_attachment_fraud_model, predict_fraud
from app.ui.report_generator import generate_summary

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def authenticate():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file('backend/credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def get_mails(service, label="SPAM"):
    result = service.users().messages().list(userId='me', labelIds=[label], maxResults=10).execute()
    messages = result.get('messages', [])
    return messages

def decode_payload(msg):
    try:
        if msg.get('payload').get('body').get('data'):
            data = base64.urlsafe_b64decode(msg['payload']['body']['data'].encode('UTF-8'))
        else:
            parts = msg['payload']['parts']
            data = base64.urlsafe_b64decode(parts[0]['body']['data'].encode('UTF-8'))
        return data.decode('utf-8', errors='ignore')
    except Exception as e:
        return ""

def classify_score(score):
    if score >= 80:
        return "Highly Risky"
    elif score >= 40:
        return "Suspicious"
    return "Safe"

def scan_email(service, msg_id, fraud_model, fraud_vectorizer):
    """
    Scan an email using advanced scanners and return a risk score, findings, and summary.
    """
    # Fetch email details
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    payload = msg['payload']
    headers = {h['name']: h['value'] for h in payload.get('headers', [])}
    content = decode_payload(msg)

    # Perform checks
    links = extract_links(content)
    attachment_present = has_attachment(payload)
    fraud_prob = predict_fraud(content, attachment_present, fraud_model, fraud_vectorizer)
    attachment_risk = 30 if attachment_present and fraud_prob > 0.5 else 0

    checks = {
        "Spoof Check": 30 if check_spoof(headers) else 0,
        "Suspicious Links": 30 if scan_links(links) else 0,
        "Weird Text": 20 if is_weird_sentence(content) else 0,
        "Attachment Risk": attachment_risk
    }

    # Generate summary
    summary = generate_summary(headers, content, checks)
    total_score = sum(checks.values())
    result = classify_score(total_score)
    findings = []
    for check, score in checks.items():
        if score > 0:
            findings.append(f"⚠️ {check}: {summary[check]}")

    return total_score, findings, summary, result

def main():
    # Train attachment fraud model
    fraud_model, fraud_vectorizer = train_attachment_fraud_model()

    # Authenticate and fetch emails
    creds = authenticate()
    service = build('gmail', 'v1', credentials=creds)
    messages = get_mails(service)

    print(f"🔍 Scanning {len(messages)} spam emails...\n")

    for msg_meta in messages:
        msg_id = msg_meta['id']
        score, findings, summary, result = scan_email(service, msg_id, fraud_model, fraud_vectorizer)

        # Print results
        print("="*50)
        print(f"📧 Subject: {summary['Subject']}")
        print(f"🔢 Score: {score}/110 → {result}")
        for f in findings:
            print(f"- {f}")
        print("="*50)
        print()

        # Move safe emails out of spam
        if result == "Safe":
            service.users().messages().modify(userId='me', id=msg_id, body={
                'removeLabelIds': ['SPAM'],
                'addLabelIds': ['INBOX']
            }).execute()

if __name__ == '__main__':
    main()