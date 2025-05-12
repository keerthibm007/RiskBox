import re

def is_weird_sentence(text):
    # Basic heuristics
    if len(text.split()) < 5 or re.search(r"(win|bitcoin|urgent|click here)", text.lower()):
        return True
    return False
