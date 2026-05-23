import json
import re


def load_json(path):
    f = open(path, "r")
    data = json.load(f)
    f.close()
    return data


def get_display_name(from_line):
    if "<" in from_line:
        name = from_line.split("<")[0]
        name = name.replace('"', "")
        name = name.strip()
        return name
    return ""


def get_email_address(from_line):
    if "<" in from_line and ">" in from_line:
        email = from_line.split("<")[1]
        email = email.split(">")[0]
        return email.strip()
    return from_line.strip()


def get_domain(email):
    if "@" in email:
        return email.split("@")[1].lower()
    return ""


def looks_like_brand(text, brand):
    text = text.lower()
    if brand in text:
        return True
    return False


def check_character_substitution(domain, real_domain):
    subs = {"1": "l", "0": "o", "|": "l", "5": "s", "3": "e"}
    fixed = ""
    for c in domain:
        if c in subs:
            fixed = fixed + subs[c]
        else:
            fixed = fixed + c
    if fixed == real_domain and domain != real_domain:
        return True
    return False


def check_homograph(domain):
    for c in domain:
        if ord(c) > 127:
            return True
    return False


def analyze_sender(email_data):
    keywords = load_json("data/trusted_domains.json")
    brand_names = keywords["brand_names"]
    free_providers = keywords["free_email_providers"]
    trusted = keywords["trusted_domains"]

    result = {}
    result["red_flags"] = []
    result["green_flags"] = []

    from_line = email_data.get("from", "")
    display_name = get_display_name(from_line)
    email_address = get_email_address(from_line)
    domain = get_domain(email_address)

    result["display_name"] = display_name
    result["email_address"] = email_address
    result["domain"] = domain

    found_brand = ""
    for brand in brand_names:
        if looks_like_brand(display_name, brand):
            found_brand = brand
            break

    if found_brand != "":
        real_domain = brand_names[found_brand]
        result["claimed_brand"] = found_brand
        result["real_domain"] = real_domain

        if domain != real_domain:
            if check_character_substitution(domain, real_domain):
                result["red_flags"].append("Character substitution domain: " + domain + " (looks like " + real_domain + ")")
            elif found_brand in domain and domain != real_domain:
                result["red_flags"].append("Lookalike domain with extra words: " + domain + " is not " + real_domain)
            elif found_brand not in domain:
                result["red_flags"].append("Domain mismatch: display says " + found_brand + " but email domain is " + domain)
            else:
                result["red_flags"].append("Domain spoofing detected: " + domain + " is not " + real_domain)

        if domain in free_providers:
            result["red_flags"].append("Company name used but sent from free email provider: " + domain)

    if check_homograph(domain):
        result["red_flags"].append("Homograph attack: domain contains non-english characters")

    spf = email_data.get("spf", "none").lower()
    dkim = email_data.get("dkim", "none").lower()
    dmarc = email_data.get("dmarc", "none").lower()

    result["spf"] = spf.upper()
    result["dkim"] = dkim.upper()
    result["dmarc"] = dmarc.upper()

    if spf == "pass":
        result["green_flags"].append("Valid SPF record")
    else:
        result["red_flags"].append("SPF record failing or missing")

    if dkim == "pass":
        result["green_flags"].append("Valid DKIM record")
    else:
        result["red_flags"].append("DKIM record failing or missing")

    if dmarc == "pass":
        result["green_flags"].append("Valid DMARC record")
    else:
        result["red_flags"].append("DMARC record failing or missing")

    domain_age = email_data.get("domain_age_days", -1)
    result["domain_age_days"] = domain_age

    if domain_age >= 0 and domain_age < 30:
        result["red_flags"].append("Domain too new: created " + str(domain_age) + " days ago")

    if domain in trusted:
        result["green_flags"].append("Sender is a known trusted domain")

    return result
