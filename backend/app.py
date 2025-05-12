import base64
import os
import re
import mimetypes
import time
from bs4 import BeautifulSoup
from email import message_from_bytes
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def authenticate():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file('backend\credentials.json', SCOPES)
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

def scan_email(content):
    score = 0
    findings = []

    # 1. Link/domain scan
    links = re.findall(r'https?://[^\s]+', content)
    if links:
        score += 2
        findings.append(f"⚠️ Contains {len(links)} suspicious link(s)")

    # 2. Spoof check (basic)
    if "amazon" in content.lower() and not from_domain(content, "amazon.com"):
        score += 3
        findings.append("🚨 Possible spoofing (mentions brand but not from domain)")

    # 3. Attachment scan (mock)
    if ".exe" in content or ".zip" in content:
        score += 2
        findings.append("📎 Dangerous attachment type mentioned")

    # 4. NLP-based sentence anomaly (mock)
    if "urgent action required" in content.lower() or "click here to secure":
        score += 2
        findings.append("🧠 Suspicious language pattern")

    return score, findings

def from_domain(content, domain):
    match = re.search(r'From: .*?@([^\s]+)', content)
    if match:
        return domain in match.group(1)
    return False

def classify_score(score):
    if score >= 6:
        return "Highly Risky"
    elif score >= 3:
        return "Suspicious"
    return "Safe"

def main():
    creds = authenticate()
    service = build('gmail', 'v1', credentials=creds)
    messages = get_mails(service)

    print(f"🔍 Scanning {len(messages)} spam emails...\n")

    for msg_meta in messages:
        msg = service.users().messages().get(userId='me', id=msg_meta['id'], format='full').execute()
        content = decode_payload(msg)
        score, summary = scan_email(content)
        result = classify_score(score)

        print("="*50)
        print(f"📧 Subject: {msg['snippet']}")
        print(f"🔢 Score: {score} → {result}")
        for f in summary:
            print(f"- {f}")
        print("="*50)
        print()

        # Example: Move safe emails out of spam
        if result == "Safe":
            service.users().messages().modify(userId='me', id=msg['id'], body={
                'removeLabelIds': ['SPAM'],
                'addLabelIds': ['INBOX']
            }).execute()

if __name__ == '__main__':
    main()
