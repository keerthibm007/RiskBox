def generate_summary(headers, content, checks):
    summary = {
        "From": headers.get("From", "Unknown"),
        "Subject": headers.get("Subject", "No Subject"),
        "Checks": checks,
        "Risk Score": sum(checks.values())
    }

    level = "Safe"
    score = summary["Risk Score"]
    if score >= 60:
        level = "High Risk"
    elif score >= 30:
        level = "Moderate Risk"
    
    summary["Risk Level"] = level
    return summary
