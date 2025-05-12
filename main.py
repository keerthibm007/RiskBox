from app.gmail_client import authenticate_gmail, fetch_messages, get_email_content
from app.scanners.spoof_checker import check_spoof
from app.scanners.link_scanner import extract_links, scan_links
from app.scanners.nlp_checker import is_weird_sentence
from app.ui.report_generator import generate_summary

def main():
    service = authenticate_gmail()
    messages = fetch_messages(service)

    print(f"Found {len(messages)} messages.")

    for msg in messages[:5]:  # limit for demo
        msg_id = msg['id']
        headers, content = get_email_content(service, msg_id)
        links = extract_links(content)

        checks = {
            "Spoof Check": 30 if check_spoof(headers) else 0,
            "Suspicious Links": 30 if scan_links(links) else 0,
            "Weird Text": 20 if is_weird_sentence(content) else 0,
        }

        summary = generate_summary(headers, content, checks)
        print("\n📧 EMAIL SUMMARY:")
        for k, v in summary.items():
            print(f"{k}: {v}")

if __name__ == '__main__':
    main()
