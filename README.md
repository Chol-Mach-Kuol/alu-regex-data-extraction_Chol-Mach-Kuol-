# ALU Regex Data Extraction and Secure Validation

## Overview

This project extracts structured data from raw text using Regular Expressions (Regex).

The system validates and safely processes external input while demonstrating awareness of security risks such as:

- Script injection
- SQL injection attempts
- Path traversal
- Unsafe URLs

The project uses Python.

---

## Features

The program extracts:

- Email addresses
- ALU-specific email addresses
- URLs
- Phone numbers
- Credit card numbers
- Time values

---

## ALU Email Validation

The system validates these ALU email formats:

- @alueducation.com
- @alumni.alueducation.com
- @si.alueducation.com

Examples:

- john@alueducation.com
- user@alumni.alueducation.com
- student@si.alueducation.com

---

## Security Considerations

The program assumes external input is untrusted.

It detects suspicious patterns such as:

- `<script>` tags
- `DROP TABLE`
- Path traversal (`../../`)
- `javascript:` URLs

Sensitive data such as credit card numbers are masked before output.

Example:

- Original: 4532 0151 1283 0366
- Output: \*\*\*\* \*\*\*\* \*\*\*\* 0366

Cards where all digits are identical (e.g. `0000 0000 0000 0000`) are rejected as trivially invalid before masking. Known sequential test numbers (e.g. `1234 5678 9999 0000`) are also rejected.

---

## How to Run

### Step 1

Navigate into the project directory.

```bash
cd alu-regex-data-extraction_CholMachKuol
```

### Step 2

Run the program.

```bash
python3 src/main.py
```

### Step 3

View results inside:

```
output/sample-output.json
```

---

## Regex Summary

### Email Regex
```
r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
```
Matches valid email addresses. Rejects double-@ (`admin@@`), missing TLD (`fake@alueducation`), and bare domains. ALU alumni and SI patterns are applied before the staff pattern to prevent `@alumni.alueducation.com` from being partially matched as `@alueducation.com`.

### URL Regex
```
r"\bhttps?://[^\s]+"
```
Matches HTTP and HTTPS URLs including paths, query strings, and fragments. Rejects `javascript:` scheme (caught by security check) and malformed entries like `http//broken-url.com` which are missing the colon after `http`.

### Phone Regex
Supports:
- International numbers (`+250 788 123 456`, `+1-202-555-0199`)
- North American parentheses format (`(202) 555-0188`)

Uses a negative lookbehind `(?<![\d])` instead of `\b` because `\b` does not anchor before `+` (which is not a word character). Invalid entries like `abcd-123-999` and bare `999999` are not matched.

### Credit Card Regex
Supports:
- Space-separated cards (`4532 0151 1283 0366`)
- Dash-separated cards (`5500-0000-0000-0004`)

Partial numbers like `4111-1111-111` (only 15 digits) are excluded by the `\b` word boundary anchor. Cards with all identical digits and known sequential test numbers are rejected before masking.

### Time Regex
Supports:
- 24-hour format (`09:45`, `23:59`)
- 12-hour AM/PM format (`7:30 PM`)

The 12-hour branch is listed first so `7:30 PM` is captured as a full 12-hour time rather than matching only `7:30` via the 24-hour branch. Invalid minutes (e.g. `13:75`) are rejected by the `[0-5]\d` minute constraint. Invalid times like `99:99` are rejected by the hour constraints.

---

## Author

Chol Mach Kuol
