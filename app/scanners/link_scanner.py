import re

def extract_links(text):
    return re.findall(r'(https?://[^\s]+)', text)

def scan_links(links):
    return any("bit.ly" in link or "suspicious" in link for link in links)
