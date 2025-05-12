from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from base64 import urlsafe_b64decode
import os

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def authenticate_gmail():
    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
    creds = flow.run_local_server(port=0)
    return build('gmail', 'v1', credentials=creds)

def fetch_messages(service, label_ids=['SPAM']):
    results = service.users().messages().list(userId='me', labelIds=label_ids).execute()
    messages = results.get('messages', [])
    return messages

def get_email_content(service, msg_id):
    message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    payload = message['payload']
    headers = {h['name']: h['value'] for h in payload.get('headers', [])}
    body = ''

    if 'parts' in payload:
        for part in payload['parts']:
            if part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                body = urlsafe_b64decode(part['body']['data']).decode('utf-8')
    elif 'body' in payload and 'data' in payload['body']:
        body = urlsafe_b64decode(payload['body']['data']).decode('utf-8')

    return headers, body

def move_email(service, msg_id, from_label='SPAM', to_label='INBOX'):
    service.users().messages().modify(
        userId='me',
        id=msg_id,
        body={'removeLabelIds': [from_label], 'addLabelIds': [to_label]}
    ).execute()
