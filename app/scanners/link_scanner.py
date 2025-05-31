import re
import pandas as pd
import os

# Path for the dataset
DATASET_PATH = os.path.join("spoofing_csv", "PhiUSIIL_Phishing_URL_Dataset.csv")

# Load known phishing URLs from dataset
def load_phishing_urls():
    """
    Load phishing URLs from the dataset.
    """
    try:
        df = pd.read_csv(DATASET_PATH)
        if df.empty:
            raise ValueError("Dataset is empty")

        # Ensure required columns exist
        required_columns = ['URL', 'Label']
        missing_cols = [col for col in required_columns if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Missing columns in dataset: {missing_cols}")

        # Extract phishing URLs (where Label indicates phishing, e.g., 1 or "phishing")
        phishing_urls = df[df['Label'].isin([1, 'phishing'])]['URL'].tolist()
        return set(url.lower() for url in phishing_urls)
    except Exception as e:
        print(f"Error loading phishing URLs: {str(e)}")
        return set()

PHISHING_URLS = load_phishing_urls()

def extract_links(text):
    """
    Extract URLs from email content.
    """
    return re.findall(r'(https?://[^\s]+)', text)

def scan_links(links):
    """
    Scan links for suspicious activity. Returns True if any link is suspicious.
    """
    if not links:
        return False
    
    for link in links:
        link_lower = link.lower()
        # Check for known suspicious patterns
        if "bit.ly" in link_lower or "suspicious" in link_lower:
            return True
        
        # Check against known phishing URLs
        if link_lower in PHISHING_URLS:
            return True
        
        # Add more checks as needed (e.g., HTTP vs HTTPS, URL length)
        if link_lower.startswith("http://"):
            return True
    
    return False