import datetime
import os


def save_report(email_data, sender, content, urls, attachments, psychology, score_data, verdict, attack, advice):
    if not os.path.exists("reports"):
        os.makedirs("reports")

    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    filename = "reports/scan_" + timestamp + ".txt"

    lines = []
    lines.append("=" * 50)
    lines.append("PHISHING EMAIL DETECTOR - FULL REPORT")
    lines.append("=" * 50)
    lines.append("Scan time: " + now.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("")

    lines.append("EMAIL DETAILS")
    lines.append("-" * 30)
    lines.append("From: " + email_data.get("from", ""))
    lines.append("Subject: " + email_data.get("subject", ""))
    lines.append("")

    lines.append("SENDER ANALYSIS")
    lines.append("-" * 30)
    lines.append("Display Name: " + sender.get("display_name", ""))
    lines.append("Actual Email: " + sender.get("email_address", ""))
    lines.append("Domain: " + sender.get("domain", ""))
    lines.append("Domain Age: " + str(sender.get("domain_age_days", "unknown")) + " days")
    lines.append("SPF: " + sender.get("spf", "NONE"))
    lines.append("DKIM: " + sender.get("dkim", "NONE"))
    lines.append("DMARC: " + sender.get("dmarc", "NONE"))
    for flag in sender["red_flags"]:
        lines.append("  [X] " + flag)
    lines.append("")

    lines.append("CONTENT ANALYSIS")
    lines.append("-" * 30)
    for flag in content["red_flags"]:
        lines.append("  [X] " + flag)
    lines.append("")

    lines.append("URL ANALYSIS")
    lines.append("-" * 30)
    lines.append("URLs found: " + str(urls.get("url_count", 0)))
    for info in urls["urls"]:
        lines.append("  " + info["url"])
        for issue in info["issues"]:
            lines.append("     -> " + issue)
    lines.append("")

    lines.append("ATTACHMENT ANALYSIS")
    lines.append("-" * 30)
    lines.append("Attachments: " + str(attachments.get("count", 0)))
    for info in attachments["attachments"]:
        lines.append("  " + info["filename"] + " (" + info["risk"] + ")")
    lines.append("")

    lines.append("PSYCHOLOGICAL TRIGGERS")
    lines.append("-" * 30)
    for flag in psychology["red_flags"]:
        lines.append("  [X] " + flag)
    lines.append("")

    lines.append("=" * 50)
    lines.append("VERDICT: " + verdict["verdict"])
    lines.append("Confidence: " + str(verdict["confidence"]) + "%")
    lines.append("Risk Level: " + verdict["risk_level"])
    lines.append("Legitimacy Score: " + str(score_data["score"]) + "/100")
    lines.append("=" * 50)
    lines.append("")

    lines.append("WHAT TO DO")
    lines.append("-" * 30)
    step = 1
    for a in advice:
        lines.append(str(step) + ". " + a)
        step = step + 1
    lines.append("")

    if verdict["verdict"] != "LEGITIMATE EMAIL" and verdict["verdict"] != "LIKELY SAFE":
        lines.append("ATTACK TYPE IDENTIFIED")
        lines.append("-" * 30)
        lines.append(attack["name"])
        lines.append(attack["description"])
        lines.append("IBM Cybersecurity Reference: " + attack["ibm_reference"])
        lines.append("=" * 50)

    text = "\n".join(lines)

    f = open(filename, "w")
    f.write(text)
    f.close()

    return filename
