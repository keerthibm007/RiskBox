import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch.nn.functional as F

# Load pre-trained spam classifier model
MODEL_NAME = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)

def is_weird_sentence(text, threshold=0.7):
    """
    Returns True if the text is considered spam (above threshold).
    """
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=512,  # Added max_length to fix the error
        padding=True
    )
    with torch.no_grad():
        outputs = model(**inputs)
        probs = F.softmax(outputs.logits, dim=1)
        spam_prob = probs[0][1].item()
        return spam_prob > threshold

def get_spam_probability(text):
    """
    Returns the spam probability score between 0 and 1.
    """
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=512,  # Added max_length here too
        padding=True
    )
    with torch.no_grad():
        outputs = model(**inputs)
        probs = F.softmax(outputs.logits, dim=1)
        return round(probs[0][1].item(), 4)
