import json


def load_json(path):
    f = open(path, "r")
    data = json.load(f)
    f.close()
    return data


def find_in_text(text, word_list):
    text = text.lower()
    found = []
    for word in word_list:
        if word in text:
            found.append(word)
    return found


def analyze_psychology(email_data):
    urgency_data = load_json("data/urgency_words.json")

    result = {}
    result["red_flags"] = []
    result["green_flags"] = []
    result["triggers"] = []

    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    full_text = subject + " " + body

    urgency = find_in_text(full_text, urgency_data["urgency"])
    if len(urgency) > 0:
        result["triggers"].append("Urgency/Scarcity")
        result["red_flags"].append("Urgency trigger: " + urgency[0])

    fear = find_in_text(full_text, urgency_data["fear"])
    if len(fear) > 0:
        result["triggers"].append("Fear")
        result["red_flags"].append("Fear trigger: " + fear[0])

    authority = find_in_text(full_text, urgency_data["authority"])
    if len(authority) > 0:
        result["triggers"].append("Authority")
        result["red_flags"].append("Authority trigger: " + authority[0])

    scarcity = find_in_text(full_text, urgency_data["scarcity"])
    if len(scarcity) > 0:
        result["triggers"].append("Scarcity")
        result["red_flags"].append("Scarcity trigger: " + scarcity[0])

    reward = find_in_text(full_text, urgency_data["reward"])
    if len(reward) > 0:
        result["triggers"].append("Reward")
        result["red_flags"].append("Reward trigger: " + reward[0])

    social = find_in_text(full_text, urgency_data["social_proof"])
    if len(social) > 0:
        result["triggers"].append("Social Proof")
        result["red_flags"].append("Social proof trigger: " + social[0])

    return result
