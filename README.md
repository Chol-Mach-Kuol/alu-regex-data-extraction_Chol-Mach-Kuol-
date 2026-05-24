# ALU Regex Data Extraction and Secure Validation

## Overview

This project reads raw text from a file and uses regular expressions to pull out specific types of data like emails, phone numbers, URLs, credit cards, and times.

It also checks the input for things that look dangerous like script tags or SQL injection and records them separately.

The project is written in Python.

---

## What it extracts

- Email addresses (general + ALU-specific)
- URLs
- Phone numbers
- Credit card numbers (masked in output)
- Times in 12-hour and 24-hour format

---

## ALU Email Validation

The program checks for three ALU email formats:

- @alueducation.com
- @alumni.alueducation.com
- @si.alueducation.com

Examples that should pass:

- john.doe@alueducation.com
- mary_kim@alumni.alueducation.com
- samuel@si.alueducation.com

Examples that should fail:

- admin@@alueducation.com (double @)
- fake@alueducation (no TLD)

---

## Security

The program does not trust the input. It scans for:

- `<script>` tags
- `DROP TABLE` statements
- `../../` path traversal
- `javascript:` URLs

Credit card numbers are never stored in full. Only the last 4 digits appear in the output like this:

- Input: 4532 0151 1283 0366
- Output: \*\*\*\* \*\*\*\* \*\*\*\* 0366

Cards like `0000 0000 0000 0000` (all same digit) and known fake numbers like `1234 5678 9999 0000` are rejected before masking.

---

## How to run

Step 1 - go into the project folder:

```bash
cd alu-regex-data-extraction_CholMachKuol
```

Step 2 - run the script:

```bash
python3 src/main.py
```

Step 3 - check the output:

```
output/sample-output.json
```

---

## Regex patterns explained

### Email
```
r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
```
Matches the local part before @, then the domain, then a TLD of at least 2 characters. I check alumni and SI patterns before the official one because @alumni.alueducation.com contains @alueducation.com inside it and would get misclassified.

### URL
```
r"\bhttps?://[^\s]+"
```
Matches http and https URLs up to the first space. javascript: doesn't match because it doesn't start with http. http//broken-url.com doesn't match because the colon is missing.

### Phone
```
(?<![\d])(\+\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3}[\s-]?\d{3,4} | \(\d{3}\)\s?\d{3}-\d{4})(?![\d])
```
Handles international numbers like +250 788 123 456 and North American like (202) 555-0188. I used `(?<![\d])` instead of `\b` because `\b` doesn't work before the + sign.

### Credit card
```
\b((?:\d{4}[- ]?){3}\d{4})\b
```
Matches 16 digits in groups of 4 with spaces or dashes. Partial numbers like 4111-1111-111 don't match because the last group needs exactly 4 digits.

### Time
```
\b(([1-9]|1[0-2]):[0-5]\d[ ]?(AM|PM) | ([01]?\d|2[0-3]):[0-5]\d)\b
```
I put the 12-hour format first so 7:30 PM gets matched fully. If 24-hour came first it would match 7:30 and stop before PM. Minutes above 59 like :75 are blocked by [0-5]\d.

---

## Author

Chol Mach Kuol
