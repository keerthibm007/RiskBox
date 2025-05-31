def generate_summary(headers, content, checks):
    total_risk = sum(checks.values())
    content_preview = content[:100] + "..." if len(content) > 100 else content
    summary = {
        "From": headers.get('From', 'Unknown'),
        "Subject": headers.get('Subject', 'No Subject'),
        "Content Preview": content_preview,
        "Risk Score": f"{total_risk}/110",  # Updated to include attachment check (30+30+20+30)
        "Spoof Check": "Failed" if checks["Spoof Check"] > 0 else "Passed",
        "Suspicious Links": "Detected" if checks["Suspicious Links"] > 0 else "None",
        "Weird Text": "Detected" if checks["Weird Text"] > 0 else "None",
        "Attachment Risk": "High" if checks["Attachment Risk"] > 0 else "Low"
    }
    return summary