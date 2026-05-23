import json
import re


def load_json(path):
    f = open(path, "r")
    data = json.load(f)
    f.close()
    return data


def count_words_from_list(text, word_list):
    text = text.lower()
    found = []
    for word in word_list:
        if word in text:
            found.append(word)
    return found


def is_all_caps(text):
    letters = ""
    for c in text:
        if c.isalpha():
            letters = letters + c
    if len(letters) < 3:
        return False
    if letters == letters.upper():
        return True
    return False


def count_grammar_errors(text):
    errors = 0
    common_mistakes = [
        "kindly do the needful",
        "your account have",
        "we is",
        "you has",
        "please to",
        "verify you account",
        "click here immediately",
        "dear costumer",
        "we detected a unusual",
        "informations",
        "kindly revert"
    ]
    text_low = text.lower()
    for mistake in common_mistakes:
        if mistake in text_low:
            errors = errors + 1

    sentences = text.split(".")
    for s in sentences:
        s = s.strip()
        if len(s) > 0:
            first = s[0]
            if first.islower() and first.isalpha():
                errors = errors + 1
    return errors


def analyze_content(email_data):
    urgency_data = load_json("data/urgency_words.json")
    keywords = load_json("data/phishing_keywords.json")

    result = {}
    result["red_flags"] = []
    result["green_flags"] = []

    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    full_text = subject + " " + body

    result["subject"] = subject

    urgency_found = count_words_from_list(full_text, urgency_data["urgency"])
    fear_found = count_words_from_list(full_text, urgency_data["fear"])
    reward_found = count_words_from_list(full_text, urgency_data["reward"])

    result["urgency_words"] = urgency_found
    result["fear_words"] = fear_found
    result["reward_words"] = reward_found

    if len(urgency_found) > 0:
        result["red_flags"].append("Urgency words found: " + ", ".join(urgency_found))

    if len(fear_found) > 0:
        result["red_flags"].append("Threat/fear words found: " + ", ".join(fear_found))

    if len(reward_found) > 0:
        result["red_flags"].append("Reward/prize words found: " + ", ".join(reward_found))

    if is_all_caps(subject):
        result["red_flags"].append("Subject line is all capitals (shouting)")

    greetings_found = count_words_from_list(body, keywords["generic_greetings"])
    result["generic_greetings"] = greetings_found
    if len(greetings_found) > 0:
        result["red_flags"].append("Generic greeting used: " + greetings_found[0])

    cred_found = count_words_from_list(body, keywords["credential_requests"])
    result["credential_requests"] = cred_found
    if len(cred_found) > 0:
        result["red_flags"].append("Credential request detected: " + cred_found[0])

    threat_found = count_words_from_list(body, keywords["threatening"])
    result["threatening"] = threat_found
    if len(threat_found) > 0:
        result["red_flags"].append("Threatening language: " + threat_found[0])

    impersonation_found = count_words_from_list(body, keywords["impersonation"])
    result["impersonation"] = impersonation_found

    errors = count_grammar_errors(body)
    result["grammar_errors"] = errors
    if errors > 0:
        result["red_flags"].append("Grammar/spelling errors detected: " + str(errors))

    body_low = body.lower()
    if "unsubscribe" in body_low:
        result["green_flags"].append("Has unsubscribe link")
        result["has_unsubscribe"] = True
    else:
        result["has_unsubscribe"] = False

    has_phone = False
    phone_pattern = re.findall(r"\+?\d[\d\s\-]{7,}\d", body)
    if len(phone_pattern) > 0:
        has_phone = True
        result["green_flags"].append("Contains a phone number")
    result["has_phone"] = has_phone

    address_words = ["street", "avenue", "road", "suite", "p.o. box", "inc.", "ltd", "blvd"]
    has_address = False
    for w in address_words:
        if w in body_low:
            has_address = True
            break
    if has_address:
        result["green_flags"].append("Contains a company address")
    result["has_address"] = has_address

    return result
