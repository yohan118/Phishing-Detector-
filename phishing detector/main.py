import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from analyzers import sender_analyzer
from analyzers import content_analyzer
from analyzers import url_analyzer
from analyzers import attachment_analyzer
from analyzers import psychology_analyzer
from engines import scoring_engine
from engines import verdict_engine
from engines import attack_classifier
from reporter import report_generator

from parse_eml import parse_real_eml

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def parse_email(raw):
    email_data = {}
    email_data["attachments"] = []

    lines = raw.split("\n")
    body_lines = []
    in_body = False

    for line in lines:
        low = line.lower()
        if in_body:
            body_lines.append(line)
            continue

        if low.startswith("from:"):
            email_data["from"] = line[5:].strip()
        elif low.startswith("subject:"):
            email_data["subject"] = line[8:].strip()
        elif low.startswith("spf:"):
            email_data["spf"] = line[4:].strip()
        elif low.startswith("dkim:"):
            email_data["dkim"] = line[5:].strip()
        elif low.startswith("dmarc:"):
            email_data["dmarc"] = line[6:].strip()
        elif low.startswith("domain-age:"):
            try:
                email_data["domain_age_days"] = int(line[11:].strip())
            except:
                email_data["domain_age_days"] = -1
        elif low.startswith("attachment:"):
            email_data["attachments"].append(line[11:].strip())
        elif line.strip() == "":
            in_body = True
        else:
            pass

    email_data["body"] = "\n".join(body_lines)
    return email_data


def print_section(title):
    console.print()
    console.print("[bold cyan]" + title + "[/bold cyan]")
    console.print("[cyan]" + ("-" * len(title)) + "[/cyan]")


def run_analysis(raw):
    email_data = parse_email(raw)
    display_results(email_data)


def run_analysis_eml(filepath):
    email_data = parse_real_eml(filepath)
    display_results(email_data)


def display_results(email_data):
    console.print(Panel("[bold]PHISHING EMAIL DETECTOR[/bold]", expand=False))
    console.print("Analyzing email...")

    sender = sender_analyzer.analyze_sender(email_data)
    content = content_analyzer.analyze_content(email_data)
    urls = url_analyzer.analyze_urls(email_data)
    attachments = attachment_analyzer.analyze_attachments(email_data)
    psychology = psychology_analyzer.analyze_psychology(email_data)

    score_data = scoring_engine.calculate_score(sender, content, urls, attachments, psychology)
    verdict = verdict_engine.get_verdict(score_data["score"])
    advice = verdict_engine.get_advice(verdict["verdict"])
    attack = attack_classifier.classify_attack(sender, content, urls, attachments, psychology)

    print_section("SENDER ANALYSIS")
    console.print("Display Name:  " + sender.get("display_name", ""))
    console.print("Actual Email:  " + sender.get("email_address", ""))
    console.print("Domain Age:    " + str(sender.get("domain_age_days", "unknown")) + " days")
    console.print("SPF:   " + sender.get("spf", "NONE"))
    console.print("DKIM:  " + sender.get("dkim", "NONE"))
    console.print("DMARC: " + sender.get("dmarc", "NONE"))
    for flag in sender["red_flags"]:
        console.print("[red]X " + flag + "[/red]")
    for flag in sender["green_flags"]:
        console.print("[green]OK " + flag + "[/green]")

    print_section("CONTENT ANALYSIS")
    console.print("Subject: " + content.get("subject", ""))
    for flag in content["red_flags"]:
        console.print("[red]X " + flag + "[/red]")
    for flag in content["green_flags"]:
        console.print("[green]OK " + flag + "[/green]")

    print_section("URL ANALYSIS")
    console.print("URLs found: " + str(urls.get("url_count", 0)))
    for info in urls["urls"]:
        if len(info["issues"]) > 0:
            console.print("[red]X " + info["url"] + "[/red]")
            for issue in info["issues"]:
                console.print("    -> " + issue)
        else:
            console.print("[green]OK " + info["url"] + "[/green]")

    print_section("ATTACHMENT ANALYSIS")
    console.print("Attachments: " + str(attachments.get("count", 0)))
    for info in attachments["attachments"]:
        if info["risk"] == "CRITICAL" or info["risk"] == "HIGH":
            console.print("[red]X " + info["filename"] + " - " + info["risk"] + "[/red]")
        else:
            console.print(info["filename"] + " - " + info["risk"])

    print_section("PSYCHOLOGICAL TRIGGERS")
    for flag in psychology["red_flags"]:
        console.print("[red]X " + flag + "[/red]")
    if len(psychology["red_flags"]) == 0:
        console.print("None detected")

    red_count = len(sender["red_flags"]) + len(content["red_flags"]) + len(urls["red_flags"]) + len(attachments["red_flags"]) + len(psychology["red_flags"])
    green_count = len(sender["green_flags"]) + len(content["green_flags"]) + len(urls["green_flags"])

    console.print()
    verdict_text = verdict["emoji"] + " VERDICT: " + verdict["verdict"]
    box = verdict_text + "\n"
    box = box + "Confidence: " + str(verdict["confidence"]) + "%\n"
    box = box + "Risk Level: " + verdict["risk_level"] + "\n"
    box = box + "Legitimacy Score: " + str(score_data["score"]) + "/100\n\n"
    box = box + "Red flags found: " + str(red_count) + "\n"
    box = box + "Legitimate signs: " + str(green_count)
    console.print(Panel(box, border_style=verdict["color"]))

    print_section("WHAT TO DO")
    step = 1
    for a in advice:
        console.print(str(step) + ". " + a)
        step = step + 1

    if verdict["verdict"] != "LEGITIMATE EMAIL" and verdict["verdict"] != "LIKELY SAFE":
        print_section("ATTACK TYPE IDENTIFIED")
        console.print("[bold]" + attack["name"] + "[/bold]")
        console.print(attack["description"])
        
    filename = report_generator.save_report(email_data, sender, content, urls, attachments, psychology, score_data, verdict, attack, advice)
    console.print()
    console.print("[bold]FULL REPORT SAVED:[/bold] " + filename)


def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if path.endswith(".eml"):
            run_analysis_eml(path)
        else:
            f = open(path, "r")
            raw = f.read()
            f.close()
            run_analysis(raw)
    else:
        console.print("Paste the raw email below. Type END on a new line when done.")
        console.print()
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip() == "END":
                break
            lines.append(line)
        raw = "\n".join(lines)
        run_analysis(raw)


if __name__ == "__main__":
    main()
