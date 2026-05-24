import re
import json
from pathlib import Path

# =========================
# READ INPUT FILE
# =========================

# Resolve paths relative to this script so the program runs correctly
# regardless of which directory it is launched from.
BASE_DIR = Path(__file__).resolve().parent.parent
input_path = BASE_DIR / "input" / "raw-text.txt"

with open(input_path, "r", encoding="utf-8") as file:
    raw_text = file.read()

# =========================
# SECURITY CHECKS
# =========================

# Scan the raw input for known hostile patterns BEFORE any extraction.
# We do not trust external input automatically.
# Matches are recorded in security_alerts and included in the output
# so the caller knows what was detected.

malicious_patterns = [
    r"<script.*?>.*?</script>",   # XSS: script tag injection
    r"DROP\s+TABLE",              # SQL injection: destructive statement
    r"\.\./\.\./",                # Path traversal: directory escape attempt
    r"javascript:"                # XSS: javascript: URI scheme
]

security_alerts = []

for pattern in malicious_patterns:
    matches = re.findall(pattern, raw_text, re.IGNORECASE)
    security_alerts.extend(matches)

# =========================
# REGEX PATTERNS
# =========================

# EMAILS
# Matches a local part (alphanumeric, dots, underscores, percent, plus, hyphen)
# followed by @ and a domain with at least one dot and a 2+ char TLD.
# Rejects: double-@ (admin@@), missing TLD (fake@alueducation), bare domains.
email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"

# ALU-SPECIFIC EMAIL VALIDATION
# Three separate patterns for each official ALU domain.
# Alumni and SI patterns are applied before the staff pattern to prevent
# @alumni.alueducation.com from being partially matched as @alueducation.com.
alu_official_pattern = r"\b[a-zA-Z0-9._%+-]+@alueducation\.com\b"
alu_alumni_pattern   = r"\b[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com\b"
alu_si_pattern       = r"\b[a-zA-Z0-9._%+-]+@si\.alueducation\.com\b"

# URLS
# Matches http:// and https:// URLs including paths, query strings, and fragments.
# Stops at the first whitespace character.
# Rejects: javascript: scheme (caught by security check above),
#          malformed entries like http//broken-url.com (missing colon after http).
url_pattern = r"\bhttps?://[^\s]+"

# PHONE NUMBERS
# Supports two real-world formats:
#   International: +<country code> followed by digit groups (spaces or hyphens).
#   North American: (NXX) NXX-XXXX
# NOTE: \b cannot anchor before + because + is not a word character.
#       (?<![\d]) is used instead to prevent matching mid-number.
phone_pattern = r"""
(?<![\d])(
    \+\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3}[\s-]?\d{3,4}
    |
    \(\d{3}\)\s?\d{3}-\d{4}
)(?![\d])
"""

# CREDIT CARD NUMBERS
# Matches 16-digit card numbers in groups of 4, separated by a space or hyphen.
# Partial numbers like 4111-1111-111 (only 15 digits) are excluded by \b.
credit_card_pattern = r"""
\b(
    (?:\d{4}[- ]?){3}\d{4}
)\b
"""

# TIME FORMATS
# Supports both 12-hour and 24-hour formats.
# 12-hour branch is listed FIRST so that "7:30 PM" is captured as a complete
# 12-hour time rather than matching only "7:30" via the 24-hour branch.
# Invalid minutes (e.g. 13:75) are rejected by the [0-5]\d minute constraint.
# Invalid hours (e.g. 99:99 PM) are rejected by the (1-9|1[0-2]) hour constraint.
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
# re.findall with one capturing group returns a flat list of strings (not tuples)
phones = [p for p in phones if p]

credit_cards = re.findall(credit_card_pattern, raw_text, re.VERBOSE)
credit_cards = [card[0] if isinstance(card, tuple) else card for card in credit_cards]

times = re.findall(time_pattern, raw_text, re.VERBOSE | re.IGNORECASE)
formatted_times = [t[0] for t in times]

# =========================
# MASK SENSITIVE DATA
# =========================

# Credit card numbers are masked before output.
# Only the last 4 digits are shown; all others are replaced with *.
# Raw card numbers are never written to the output file or printed to the console.
# Security: cards where all 16 digits are identical (e.g. 0000 0000 0000 0000)
# are rejected as trivially fake before masking.
# Known sequential test numbers are also rejected.
masked_cards = []

KNOWN_INVALID_CARDS = {
    "1234567890000000",  # sequential test pattern
    "1234567899990000",  # sequential test pattern
}

for card in credit_cards:
    digits = re.sub(r"\D", "", card)

    if len(digits) == 16:
        # Reject cards that are all the same digit — trivially invalid
        if len(set(digits)) == 1:
            continue
        # Reject known test/sequential card numbers
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
