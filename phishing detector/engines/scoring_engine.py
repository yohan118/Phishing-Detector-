def calculate_score(sender, content, urls, attachments, psychology):
    score = 100
    points_log = []

    for flag in sender["red_flags"]:
        if "Character substitution" in flag or "Lookalike domain" in flag or "Domain mismatch" in flag or "Domain spoofing" in flag or "Homograph" in flag:
            score = score - 30
            points_log.append("-30 domain spoofing")
        elif "SPF" in flag:
            score = score - 15
            points_log.append("-15 SPF fail")
        elif "DKIM" in flag:
            score = score - 15
            points_log.append("-15 DKIM fail")
        elif "DMARC" in flag:
            score = score - 15
            points_log.append("-15 DMARC fail")
        elif "Domain too new" in flag:
            score = score - 20
            points_log.append("-20 new domain")
        elif "free email provider" in flag:
            score = score - 20
            points_log.append("-20 free email provider")

    for flag in content["red_flags"]:
        if "Credential request" in flag:
            score = score - 25
            points_log.append("-25 credential request")
        elif "Urgency words" in flag:
            score = score - 10
            points_log.append("-10 urgency")
        elif "Generic greeting" in flag:
            score = score - 10
            points_log.append("-10 generic greeting")
        elif "Grammar" in flag:
            errors = content.get("grammar_errors", 0)
            score = score - (5 * errors)
            points_log.append("-" + str(5 * errors) + " grammar errors")
        elif "Threatening" in flag:
            score = score - 10
            points_log.append("-10 threatening language")

    for flag in urls["red_flags"]:
        if "HTTP link" in flag:
            score = score - 10
            points_log.append("-10 http link")
        elif "Shortened URL" in flag:
            score = score - 15
            points_log.append("-15 url shortener")
        elif "Suspicious TLD" in flag:
            score = score - 20
            points_log.append("-20 suspicious tld")
        elif "Subdomain trick" in flag:
            score = score - 20
            points_log.append("-20 subdomain trick")
        elif "Mismatched link" in flag:
            score = score - 20
            points_log.append("-20 mismatched link")
        elif "raw IP" in flag:
            score = score - 20
            points_log.append("-20 ip address url")

    for info in attachments["attachments"]:
        if info["risk"] == "CRITICAL":
            score = score - 40
            points_log.append("-40 executable attachment")
        elif info["risk"] == "HIGH":
            score = score - 20
            points_log.append("-20 compressed attachment")
        elif info["risk"] == "MEDIUM":
            score = score - 10
            points_log.append("-10 document attachment")

    for flag in sender["green_flags"]:
        if "Valid SPF" in flag:
            score = score + 10
            points_log.append("+10 valid spf")
        elif "Valid DKIM" in flag:
            score = score + 10
            points_log.append("+10 valid dkim")
        elif "trusted domain" in flag:
            score = score + 20
            points_log.append("+20 trusted domain")

    for flag in content["green_flags"]:
        if "unsubscribe" in flag:
            score = score + 5
            points_log.append("+5 unsubscribe")
        elif "address" in flag:
            score = score + 5
            points_log.append("+5 company address")
        elif "phone" in flag:
            score = score + 5
            points_log.append("+5 phone number")

    for flag in urls["green_flags"]:
        if "HTTPS" in flag:
            score = score + 10
            points_log.append("+10 all https")

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    out = {}
    out["score"] = score
    out["points_log"] = points_log
    return out
