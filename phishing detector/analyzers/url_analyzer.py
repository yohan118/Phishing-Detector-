import json
import re


def load_json(path):
    f = open(path, "r")
    data = json.load(f)
    f.close()
    return data


def find_urls(text):
    urls = []
    plain = re.findall(r"https?://[^\s\"'<>\)]+", text)
    for u in plain:
        urls.append(u)
    return urls


def find_href_links(text):
    links = []
    matches = re.findall(r'href=["\'](https?://[^"\']+)["\']', text)
    for m in matches:
        links.append(m)
    return links


def find_display_vs_actual(text):
    pairs = []
    matches = re.findall(r'href=["\'](https?://[^"\']+)["\'][^>]*>([^<]+)</a>', text)
    for actual, display in matches:
        pairs.append((display.strip(), actual.strip()))
    return pairs


def get_domain_from_url(url):
    domain = url
    domain = domain.replace("http://", "")
    domain = domain.replace("https://", "")
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    domain = domain.lower()
    return domain


def get_real_domain(domain):
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain


def is_ip_address(domain):
    pattern = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain)
    if pattern:
        return True
    return False


def analyze_urls(email_data):
    tld_data = load_json("data/suspicious_tlds.json")
    suspicious_tlds = tld_data["suspicious_tlds"]
    shorteners = tld_data["url_shorteners"]

    result = {}
    result["red_flags"] = []
    result["green_flags"] = []
    result["urls"] = []

    body = email_data.get("body", "")

    all_urls = find_urls(body)
    href_urls = find_href_links(body)
    for h in href_urls:
        if h not in all_urls:
            all_urls.append(h)

    pairs = find_display_vs_actual(body)
    for display, actual in pairs:
        display_text = display
        if "." in display_text and " " not in display_text:
            display_domain = get_domain_from_url(display_text)
            display_domain = display_domain.replace("www.", "")
            actual_domain = get_domain_from_url(actual)
            actual_domain = actual_domain.replace("www.", "")
            if display_domain != actual_domain:
                result["red_flags"].append("Mismatched link: shows " + display_domain + " but goes to " + actual_domain)

    result["url_count"] = len(all_urls)

    all_https = True
    for url in all_urls:
        url_info = {}
        url_info["url"] = url
        url_info["issues"] = []

        domain = get_domain_from_url(url)
        real_domain = get_real_domain(domain)

        if url.startswith("http://"):
            url_info["issues"].append("Uses HTTP not HTTPS")
            result["red_flags"].append("Insecure HTTP link: " + url)
            all_https = False

        for short in shorteners:
            if short in domain:
                url_info["issues"].append("URL shortener (hides real destination)")
                result["red_flags"].append("Shortened URL: " + url)
                break

        for tld in suspicious_tlds:
            if domain.endswith(tld):
                url_info["issues"].append("Suspicious TLD " + tld)
                result["red_flags"].append("Suspicious TLD in URL: " + url + " (" + tld + ")")
                break

        if is_ip_address(domain):
            url_info["issues"].append("Uses IP address instead of domain name")
            result["red_flags"].append("URL uses raw IP address: " + url)

        dots = domain.count(".")
        if dots >= 3:
            url_info["issues"].append("Possible subdomain trick, real domain is " + real_domain)
            result["red_flags"].append("Subdomain trick: " + url + " real domain is " + real_domain)

        url_info["domain"] = domain
        url_info["real_domain"] = real_domain
        result["urls"].append(url_info)

    if len(all_urls) > 0 and all_https:
        result["green_flags"].append("All links use HTTPS")

    return result
