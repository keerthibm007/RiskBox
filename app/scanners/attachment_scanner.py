def has_attachment(payload):
    if 'parts' in payload:
        for part in payload['parts']:
            if part.get("filename") and part.get("body", {}).get("attachmentId"):
                return True
    return False
