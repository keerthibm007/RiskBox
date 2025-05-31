import os
import pandas as pd
import joblib
import email
from email import policy
from app.scanners.nlp_checker import is_weird_sentence, get_spam_probability, MODEL_PATH, VEC_PATH

CSV_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "spoofing_csv")
DATASETS = ["CEAS_08", "Enron", "Ling", "malicious_phish", "Nazario", "Nigerian_Fraud", "phishing_email", "SpamAssassin"]
OUTPUT_PATH = os.path.join(CSV_DIR, "email_analysis_results.csv")

def check_spoof(headers):
    from_addr = headers.get('From', '')
    reply_to = headers.get('Reply-To', '')
    return from_addr != reply_to if reply_to else False

def load_spam_model():
    if not (os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH)):
        raise FileNotFoundError("Model or vectorizer file missing. Run nlp_checker.py to train the model.")
    return joblib.load(MODEL_PATH), joblib.load(VEC_PATH)

def parse_email(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f, policy=policy.default)
        from_addr = msg['From'] or ''
        reply_to = msg['Reply-To'] or ''
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    message = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
            else:
                message = ''
        else:
            message = msg.get_payload(decode=True).decode('utf-8', errors='ignore') if msg.get_payload() else ''
        return {
            'From': from_addr,
            'Reply-To': reply_to,
            'Message': message.strip(),
            'Dataset': os.path.basename(os.path.dirname(file_path))
        }
    except Exception as e:
        print(f"Error parsing {file_path}: {str(e)}")
        return None

def process_emails(max_emails_per_dataset=50):
    try:
        model, vectorizer = load_spam_model()
        all_results = []
        for dataset in DATASETS:
            dataset_dir = os.path.join(CSV_DIR, dataset)
            if not os.path.exists(dataset_dir):
                print(f"Dataset directory {dataset_dir} not found, skipping...")
                continue
            email_files = []
            for root, _, files in os.walk(dataset_dir):
                for file in files:
                    if file.endswith('.eml') or file.endswith('.txt'):
                        email_files.append(os.path.join(root, file))
            if not email_files:
                print(f"No email files found in {dataset_dir}, skipping...")
                continue
            print(f"\nProcessing up to {max_emails_per_dataset} emails from {dataset}...")
            dataset_results = []
            for i, file_path in enumerate(email_files[:max_emails_per_dataset]):
                email_data = parse_email(file_path)
                if not email_data or not email_data['Message']:
                    continue
                headers = {'From': email_data['From'], 'Reply-To': email_data['Reply-To']}
                is_spoofed = check_spoof(headers)
                spam_prob = get_spam_probability(email_data['Message'])
                is_spam = is_weird_sentence(email_data['Message'])
                dataset_results.append({
                    'Dataset': dataset,
                    'From': email_data['From'],
                    'Reply-To': email_data['Reply-To'],
                    'Message': email_data['Message'][:50] + "..." if len(email_data['Message']) > 50 else email_data['Message'],
                    'Is_Spoofed': is_spoofed,
                    'Spam_Probability': spam_prob,
                    'Is_Spam': is_spam
                })
                if (i + 1) % 10 == 0:
                    print(f"Processed {i + 1} emails from {dataset}...")
            all_results.extend(dataset_results)
        if not all_results:
            print("No valid emails processed across all datasets.")
            return
        results_df = pd.DataFrame(all_results)
        print("\nResults:")
        print(results_df.to_string(index=False))
        results_df.to_csv(OUTPUT_PATH, index=False)
        print(f"\nResults saved to {OUTPUT_PATH}")
    except Exception as e:
        print(f"Error processing emails: {str(e)}")

if __name__ == "__main__":
    process_emails(max_emails_per_dataset=50)