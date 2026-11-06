# PII Redactor

Paste text (or drop a .txt/.csv/.md/.json/.log file) and get a copy with personal information removed.
Everything runs in the browser: a Content Security Policy blocks all network requests, so text never leaves the page.

Detects emails, phone numbers, card numbers (Luhn-checked), IBANs (checksum-checked), US SSNs, IP addresses,
dates, street addresses, ZIP/UK postcodes, names after Mr./Ms./Dr./"Name:"/"Dear"/"Regards", API keys and tokens,
plus any terms you list. Replace with consistent labels (`[EMAIL_1]`), black bars, partial masks or `[REDACTED]`.

It's a single static `index.html` with no build step. Detection is pattern based, so review the output before sharing.
