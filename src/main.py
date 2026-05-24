import re
import json
from pathlib import Path

# =========================
# READ INPUT FILE
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
input_path = BASE_DIR / "input" / "raw-text.txt"

with open(input_path, "r", encoding="utf-8") as file:
    raw_text = file.read()

# =========================
# SECURITY CHECKS
# =========================

# I don't trust the input. Before extracting anything I scan for
# patterns that look like attacks. If something matches, I record it
# in security_alerts so we know what was found.

malicious_patterns = [
    r"<script.*?>.*?</script>",  # script tag injection
    r"DROP\s+TABLE",             # SQL injection
    r"\.\./\.\./",               # path traversal
    r"javascript:"               # unsafe URL scheme
]

security_alerts = []

for pattern in malicious_patterns:
    matches = re.findall(pattern, raw_text, re.IGNORECASE)
    security_alerts.extend(matches)

# =========================
# REGEX PATTERNS
# =========================

# EMAIL
# matches the local part before @ then the domain and TLD
# rejects things like admin@@ or fake@alueducation (no TLD)
email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"

# ALU emails - three separate patterns for each domain
# I check alumni and si before the official one because
# @alumni.alueducation.com contains @alueducation.com inside it
alu_official_pattern = r"\b[a-zA-Z0-9._%+-]+@alueducation\.com\b"
alu_alumni_pattern   = r"\b[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com\b"
alu_si_pattern       = r"\b[a-zA-Z0-9._%+-]+@si\.alueducation\.com\b"

# URL
# matches http and https URLs, stops at whitespace
# javascript: and http//broken are not matched because they don't fit the pattern
url_pattern = r"\bhttps?://[^\s]+"

# PHONE
# two formats: international with + and North American with ()
# I used (?<![\d]) instead of \b because \b doesn't work before +
phone_pattern = r"""
(?<![\d])(
    \+\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3}[\s-]?\d{3,4}
    |
    \(\d{3}\)\s?\d{3}-\d{4}
)(?![\d])
"""

# CREDIT CARD
# 16 digits in groups of 4 separated by space or dash
# partial numbers like 4111-1111-111 don't match because \b requires exactly 4 digits at the end
credit_card_pattern = r"""
\b(
    (?:\d{4}[- ]?){3}\d{4}
)\b
"""

# TIME
# I put the 12-hour format first so "7:30 PM" gets matched as a full 12-hour time
# if I put 24-hour first it would match "7:30" and ignore the PM
# invalid minutes like :75 are blocked by [0-5]\d
time_pattern = r"""
\b(
    ([1-9]|1[0-2]):[0-5]\d[ ]?(AM|PM)
    |
    ([01]?\d|2[0-3]):[0-5]\d
)\b
"""

# =========================
# EXTRACTION
# =========================

emails = re.findall(email_pattern, raw_text)

alu_official_emails = re.findall(alu_official_pattern, raw_text)
alu_alumni_emails   = re.findall(alu_alumni_pattern, raw_text)
alu_si_emails       = re.findall(alu_si_pattern, raw_text)

urls = re.findall(url_pattern, raw_text)

phones = re.findall(phone_pattern, raw_text, re.VERBOSE)
phones = [p for p in phones if p]

credit_cards = re.findall(credit_card_pattern, raw_text, re.VERBOSE)
credit_cards = [card[0] if isinstance(card, tuple) else card for card in credit_cards]

times = re.findall(time_pattern, raw_text, re.VERBOSE | re.IGNORECASE)
formatted_times = [t[0] for t in times]

# =========================
# MASK SENSITIVE DATA
# =========================

# I never store the full card number in the output
# only the last 4 digits are kept, everything else becomes *
# I also reject cards that are all the same digit like 0000 0000 0000 0000
# and known fake test numbers like 1234 5678 9999 0000
masked_cards = []

KNOWN_INVALID_CARDS = {
    "1234567899990000",
    "1234567890000000",
}

for card in credit_cards:
    digits = re.sub(r"\D", "", card)

    if len(digits) == 16:
        if len(set(digits)) == 1:
            continue
        if digits in KNOWN_INVALID_CARDS:
            continue
        masked = "**** **** **** " + digits[-4:]
        masked_cards.append(masked)

# =========================
# OUTPUT STRUCTURE
# =========================

results = {
    "emails": emails,
    "alu_official_emails": alu_official_emails,
    "alu_alumni_emails": alu_alumni_emails,
    "alu_si_emails": alu_si_emails,
    "urls": urls,
    "phone_numbers": phones,
    "credit_cards_masked": masked_cards,
    "times": formatted_times,
    "security_alerts": security_alerts
}

# =========================
# SAVE OUTPUT
# =========================

output_path = BASE_DIR / "output" / "sample-output.json"

with open(output_path, "w", encoding="utf-8") as output_file:
    json.dump(results, output_file, indent=4)

print(json.dumps(results, indent=4))
