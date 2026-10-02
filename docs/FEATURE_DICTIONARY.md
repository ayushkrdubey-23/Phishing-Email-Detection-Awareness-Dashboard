# Email Feature Dictionary

## Purpose

This document explains the structured features used by the
Phishing Email Detection & Awareness Dashboard.

The features are signals used for defensive analysis.
No single feature proves that an email is phishing.

---

## 1. urgent_keyword_count

Counts urgency-related words or phrases such as:

- urgent
- immediately
- act now
- do not delay
- deadline

Higher counts may indicate pressure tactics.

---

## 2. credential_keyword_count

Counts credential-related terms such as:

- password
- login
- credentials
- OTP
- verification code
- passcode

Credential-related language may require additional investigation.

---

## 3. financial_keyword_count

Counts financial terms such as:

- payment
- invoice
- billing
- bank
- transaction
- refund

Financial language can occur in both legitimate and phishing emails,
so it must be interpreted in context.

---

## 4. threat_keyword_count

Counts threatening or consequence-related terms such as:

- suspended
- blocked
- restricted
- penalty
- locked

Threat language may be used to create fear and urgency.

---

## 5. url_count

The number of URLs extracted from the email subject, body,
and supplied URL field.

A URL count by itself does not indicate phishing.

---

## 6. suspicious_url_count

The number of URLs that trigger one or more lightweight
static indicators.

Possible indicators include:

- raw IP address
- non-HTTPS scheme
- known URL shortener
- excessive subdomains
- suspicious keywords
- unusual characters
- unusually long URL

URLs are analyzed as strings only.

---

## 7. has_ip_url

TRUE when at least one URL uses a raw IP address rather than
a normal hostname.

Example:

http://198.51.100.10/verify-account

A raw IP is a signal, not proof of malicious behavior.

---

## 8. has_shortened_url_pattern

TRUE when a URL uses a known URL-shortening hostname.

Examples of recognized shortener patterns include:

- bit.ly
- tinyurl.com
- t.co
- goo.gl

No shortened URL is opened automatically.

---

## 9. sender_domain_length

Number of characters in the extracted sender domain.

Very unusual lengths can contribute contextual information.

The value is not a direct maliciousness measurement.

---

## 10. subdomain_count

Estimated number of subdomains in the sender domain.

Example:

secure.mail.example.org

Estimated subdomain count:

2

This project uses a lightweight label-count heuristic rather than
a full public-suffix database.

---

## 11. suspicious_attachment

TRUE when the attachment filename indicates:

- executable extension
- script extension
- suspicious archive extension
- double extension

Examples:

invoice.pdf.exe
employee-form.js

No attachment is executed.

---

## 12. generic_greeting

TRUE when the email starts with a common generic greeting such as:

- Dear Customer
- Dear User
- Hello Customer
- Dear Account Holder

Generic greetings can occur in legitimate bulk communication as well,
so they are only a contextual signal.

---

## 13. contains_password_request

TRUE when the text contains a request involving:

- password
- passcode
- OTP
- verification code
- credentials

combined with action language such as:

- verify
- confirm
- provide
- enter
- submit

This feature attempts to detect an actual request rather than merely
the presence of the word "password".

---

## 14. contains_personal_info_request

TRUE when the message appears to request information such as:

- personal details
- identity
- address
- phone number
- date of birth
- contact details

combined with request/verification language.

---

## 15. exclamation_count

Counts `!` characters in the subject and body.

Multiple exclamation marks may indicate emotionally charged or
urgent communication.

Legitimate promotional or announcement emails can also contain
multiple exclamation marks.

---

## 16. uppercase_ratio

Ratio of uppercase alphabetic characters to all alphabetic
characters.

Formula:

uppercase letters / total alphabetic letters

Range:

0.0 to 1.0

A high value can be a formatting signal but is not proof of phishing.

---

## 17. body_length

Number of characters in the normalized email body.

Message length can provide contextual information for later
feature analysis and machine-learning models.

---

## 18. subject_length

Number of characters in the normalized email subject.

Subject length can contribute to later analysis of short,
urgent, or unusually formatted subjects.

---

## Important Security Principle

No single feature guarantees that an email is phishing.

The project combines multiple signals with:

- sender analysis
- content analysis
- URL analysis
- attachment analysis
- rule-based scoring
- optional machine learning
- explainable findings
- analyst review

** This reduces dependence on one indicator and helps address**
** false positives and false negatives.**
