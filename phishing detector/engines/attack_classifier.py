import json


def load_json(path):
    f = open(path, "r")
    data = json.load(f)
    f.close()
    return data


def classify_attack(sender, content, urls, attachments, psychology):
    patterns = load_json("data/attack_patterns.json")["attack_patterns"]

    has_executable = False
    for info in attachments["attachments"]:
        if info["risk"] == "CRITICAL" or info["risk"] == "HIGH":
            has_executable = True

    has_credential_request = len(content.get("credential_requests", [])) > 0
    has_brand = sender.get("claimed_brand", "") != ""
    has_reward = len(content.get("reward_words", [])) > 0
    has_authority = "Authority" in psychology.get("triggers", [])
    body = content.get("subject", "").lower()
    has_invoice = "invoice" in body or "payment" in body or "bill" in body

    if has_executable:
        chosen = "malware_delivery"
    elif has_reward:
        chosen = "prize_scam"
    elif has_invoice:
        chosen = "invoice_fraud"
    elif has_authority and not has_brand:
        chosen = "business_email_compromise"
    elif has_credential_request and has_brand:
        chosen = "brand_impersonation"
    elif has_credential_request:
        chosen = "credential_harvesting"
    elif has_brand:
        chosen = "brand_impersonation"
    else:
        chosen = "generic_phishing"

    return patterns[chosen]
