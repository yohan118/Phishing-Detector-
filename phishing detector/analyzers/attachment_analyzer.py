def get_extension(filename):
    if "." in filename:
        parts = filename.lower().split(".")
        return "." + parts[-1]
    return ""


def has_double_extension(filename):
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        fake_exts = ["pdf", "doc", "docx", "jpg", "png", "txt", "xls"]
        real_exts = ["exe", "bat", "vbs", "ps1", "scr", "com", "js"]
        if parts[-2] in fake_exts and parts[-1] in real_exts:
            return True
    return False


def get_risk_level(ext):
    critical = [".exe", ".bat", ".vbs", ".ps1", ".scr", ".com", ".js", ".jar"]
    high = [".zip", ".rar", ".7z", ".iso"]
    medium = [".pdf", ".docx", ".doc", ".xlsm", ".xls"]

    if ext in critical:
        return "CRITICAL"
    if ext in high:
        return "HIGH"
    if ext in medium:
        return "MEDIUM"
    return "LOW"


def analyze_attachments(email_data):
    result = {}
    result["red_flags"] = []
    result["green_flags"] = []
    result["attachments"] = []

    attachments = email_data.get("attachments", [])
    result["count"] = len(attachments)

    urgency_words = ["urgent", "invoice", "payment", "important", "confidential", "scan"]

    for filename in attachments:
        info = {}
        info["filename"] = filename
        ext = get_extension(filename)
        info["extension"] = ext
        risk = get_risk_level(ext)
        info["risk"] = risk

        if has_double_extension(filename):
            info["risk"] = "CRITICAL"
            result["red_flags"].append("Double extension trick: " + filename + " (looks safe but is executable)")
        elif risk == "CRITICAL":
            result["red_flags"].append("Dangerous executable attachment: " + filename)
        elif risk == "HIGH":
            result["red_flags"].append("Compressed file could hide malware: " + filename)
        elif risk == "MEDIUM":
            result["red_flags"].append("Document could contain macros/scripts: " + filename)

        name_low = filename.lower()
        for w in urgency_words:
            if w in name_low and (risk == "CRITICAL" or risk == "HIGH"):
                result["red_flags"].append("Attachment name uses pressure word: " + filename)
                break

        result["attachments"].append(info)

    return result
