from app.gmail_client import authenticate_gmail, fetch_messages, get_email_content
from app.scanners.spoof_checker import check_spoof
from app.scanners.link_scanner import extract_links, scan_links
from app.scanners.nlp_checker import is_weird_sentence
from app.scanners.attachment_scanner import has_attachment, train_attachment_fraud_model, predict_fraud
from app.ui.report_generator import generate_summary

def main():
    # Train attachment fraud model
    fraud_model, fraud_vectorizer = train_attachment_fraud_model()

    # Authenticate and fetch Gmail messages
    service = authenticate_gmail()
    messages = fetch_messages(service)

    print(f"Found {len(messages)} messages.")

    for msg in messages[:5]:  # Limit for demo
        msg_id = msg['id']
        headers, content = get_email_content(service, msg_id)
        payload = service.users().messages().get(userId='me', id=msg_id, format='full').execute()['payload']
        links = extract_links(content)

        # Check for attachments and predict fraud
        attachment_present = has_attachment(payload)
        fraud_prob = predict_fraud(content, attachment_present, fraud_model, fraud_vectorizer)
        attachment_risk = 30 if attachment_present and fraud_prob > 0.5 else 0

        checks = {
            "Spoof Check": 30 if check_spoof(headers) else 0,
            "Suspicious Links": 30 if scan_links(links) else 0,
            "Weird Text": 20 if is_weird_sentence(content) else 0,
            "Attachment Risk": attachment_risk
        }

        summary = generate_summary(headers, content, checks)
        print("\n📧 EMAIL SUMMARY:")
        for k, v in summary.items():
            print(f"{k}: {v}")

if __name__ == '__main__':
    main()