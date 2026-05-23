def get_verdict(score):
    result = {}

    if score <= 30:
        result["verdict"] = "PHISHING EMAIL"
        result["confidence"] = 100 - score + 67
        if result["confidence"] > 100:
            result["confidence"] = 97 + (30 - score) // 10
        result["confidence"] = min(result["confidence"], 100)
        result["risk_level"] = "CRITICAL"
        result["color"] = "red"
        result["emoji"] = "🔴"
    elif score <= 50:
        result["verdict"] = "PHISHING EMAIL"
        result["confidence"] = 75 + (50 - score)
        result["risk_level"] = "HIGH"
        result["color"] = "red"
        result["emoji"] = "🔴"
    elif score <= 70:
        result["verdict"] = "SUSPICIOUS EMAIL"
        result["confidence"] = 50 + (70 - score)
        result["risk_level"] = "MEDIUM"
        result["color"] = "yellow"
        result["emoji"] = "🟡"
    elif score <= 85:
        result["verdict"] = "LIKELY SAFE"
        result["confidence"] = 60 + (score - 71)
        result["risk_level"] = "LOW"
        result["color"] = "green"
        result["emoji"] = "🟢"
    else:
        result["verdict"] = "LEGITIMATE EMAIL"
        result["confidence"] = 75 + (score - 86)
        result["risk_level"] = "SAFE"
        result["color"] = "green"
        result["emoji"] = "✅"

    if result["confidence"] < 0:
        result["confidence"] = 0
    if result["confidence"] > 100:
        result["confidence"] = 100

    return result


def get_advice(verdict):
    if verdict == "PHISHING EMAIL" or verdict == "SUSPICIOUS EMAIL":
        return [
            "Do NOT click any links",
            "Do NOT open attachments",
            "Do NOT reply to this email",
            "Report to IT security team",
            "Delete immediately",
            "If you clicked anything, change passwords immediately and notify IT"
        ]
    else:
        return [
            "This email looks safe based on the checks",
            "Still be careful if it asks for personal information",
            "When unsure, contact the company directly using their official website"
        ]
