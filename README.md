# Phishing Detector
A Python tool that analyzes an email and classifies it as phishing, suspicious, or legitimate. It returns a confidence score, lists every red flag, identifies the attack type, and saves a full report.
Built for a university cybersecurity project.
What it does
Reads an email and runs it through five checks:

Sender – spoofed/lookalike domains, SPF/DKIM/DMARC, domain age, free providers impersonating companies
Content – urgency/fear/reward words, generic greetings, credential requests, grammar errors
URLs – HTTP vs HTTPS, shorteners, suspicious TLDs, subdomain tricks, IP addresses, mismatched links
Attachments – dangerous extensions (.exe, .bat), double extensions (invoice.pdf.exe)
Psychology – manipulation triggers (urgency, fear, authority, scarcity, reward, social proof)

It scores the email out of 100, gives a verdict, and identifies the attack type (Brand Impersonation, Credential Harvesting, Malware Delivery, etc.).
Install
pip install rich
Python 3 required. Everything else is built in.
Run
Run on a sample:
python main.py samples/phishing_emails/bank_credential_theft.txt
Run on a real exported email (.eml):
python main.py samples/phishing_emails/real_format_paypal.eml
Or paste an email yourself (type END on its own line when done):
python main.py

Run it from inside the phishing-detector folder so it can find the data/ files.

Using real emails
Export an email from your inbox as a .eml file, then run it:

Gmail: open email → three-dot menu → Show original → Download Original
Outlook: open email → File → Save As → .eml
Apple Mail: open email → File → Save As → Raw Message Source

python main.py ~/Downloads/your-email.eml
The tool auto-detects .eml files and reads SPF/DKIM/DMARC from the real headers. Good place to find test emails: your spam folder.
Scoring
Every email starts at 100. Red flags subtract points, legitimate signs add them.
ScoreVerdictRisk0–30PhishingCRITICAL31–50PhishingHIGH51–70SuspiciousMEDIUM71–85Likely safeLOW86–100LegitimateSAFE
Example deductions: domain spoofing -30, executable attachment -40, credential request -25, suspicious TLD -20. Example additions: trusted domain +20, valid SPF +10.
Project structure
phishing-detector/
├── main.py                  ← run this
├── parse_eml.py             ← real .eml parser
├── analyzers/               ← the 5 analyzers
├── engines/                 ← scoring, verdict, attack classifier
├── data/                    ← keyword & domain JSON files
├── reporter/                ← saves reports
├── samples/                 ← test emails (phishing + legitimate)
└── reports/                 ← saved scan reports
Built with
Python 3, rich (colored output), re, json, and the built-in email library for .eml parsing. Runs fully offline.
Limitations
Rule-based, not machine learning. Domain age isn't looked up live (would need a WHOIS API). The grammar check is basic and can produce occasional false positives. This is a learning project, not a production security tool.
