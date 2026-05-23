import email
import email.header


def decode_header_value(value):
    if value is None:
        return ""
    parts = email.header.decode_header(value)
    result = ""
    for part, charset in parts:
        if isinstance(part, bytes):
            if charset:
                try:
                    result = result + part.decode(charset)
                except:
                    result = result + part.decode("utf-8", errors="replace")
            else:
                result = result + part.decode("utf-8", errors="replace")
        else:
            result = result + part
    return result


def extract_spf(msg):
    auth = msg.get("Authentication-Results", "")
    if auth == "":
        auth = msg.get("X-Google-DKIM-Signature", "")

    received_spf = msg.get("Received-SPF", "").lower()

    auth_low = auth.lower()

    if "spf=pass" in auth_low:
        return "pass"
    if "spf=fail" in auth_low:
        return "fail"
    if "spf=softfail" in auth_low:
        return "fail"
    if "spf=neutral" in auth_low:
        return "none"
    if received_spf.startswith("pass"):
        return "pass"
    if received_spf.startswith("fail"):
        return "fail"
    return "none"


def extract_dkim(msg):
    auth = msg.get("Authentication-Results", "").lower()
    dkim_sig = msg.get("DKIM-Signature", "")

    if "dkim=pass" in auth:
        return "pass"
    if "dkim=fail" in auth:
        return "fail"
    if dkim_sig != "":
        return "none"
    return "none"


def extract_dmarc(msg):
    auth = msg.get("Authentication-Results", "").lower()

    if "dmarc=pass" in auth:
        return "pass"
    if "dmarc=fail" in auth:
        return "fail"
    return "none"


def extract_body(msg):
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition:
                continue

            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset()
                    if charset:
                        try:
                            body = body + payload.decode(charset, errors="replace")
                        except:
                            body = body + payload.decode("utf-8", errors="replace")
                    else:
                        body = body + payload.decode("utf-8", errors="replace")

            elif content_type == "text/html" and body == "":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset()
                    if charset:
                        try:
                            body = body + payload.decode(charset, errors="replace")
                        except:
                            body = body + payload.decode("utf-8", errors="replace")
                    else:
                        body = body + payload.decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset()
            if charset:
                try:
                    body = payload.decode(charset, errors="replace")
                except:
                    body = payload.decode("utf-8", errors="replace")
            else:
                body = payload.decode("utf-8", errors="replace")

    return body


def extract_attachments(msg):
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                filename = part.get_filename()
                if filename:
                    filename = decode_header_value(filename)
                    attachments.append(filename)

    return attachments


def parse_real_eml(filepath):
    f = open(filepath, "r", errors="replace")
    raw = f.read()
    f.close()

    msg = email.message_from_string(raw)

    email_data = {}
    email_data["attachments"] = []

    email_data["from"]    = decode_header_value(msg.get("From", ""))
    email_data["subject"] = decode_header_value(msg.get("Subject", ""))

    email_data["spf"]   = extract_spf(msg)
    email_data["dkim"]  = extract_dkim(msg)
    email_data["dmarc"] = extract_dmarc(msg)

    email_data["domain_age_days"] = -1

    email_data["body"] = extract_body(msg)
    email_data["attachments"] = extract_attachments(msg)

    return email_data
