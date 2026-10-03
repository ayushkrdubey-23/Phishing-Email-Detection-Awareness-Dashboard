# Phishing Email Detection & Awareness Dashboard

A defensive cybersecurity application for analyzing synthetic or authorized email samples and identifying phishing indicators through sender analysis, content analysis, URL inspection, attachment metadata analysis, rule-based scoring, machine learning, and explainable risk assessment.

## Overview

Phishing is a social-engineering technique in which attackers attempt to manipulate users into performing unsafe actions such as clicking malicious-looking links, disclosing credentials, opening suspicious attachments, or following fraudulent instructions.

This project demonstrates how a cybersecurity analyst can combine multiple signals instead of relying on a single indicator.

The dashboard accepts safe email samples, analyzes their characteristics, produces an explainable phishing risk assessment, stores analysis metadata, and presents security analytics and awareness guidance.

### Defensive Scope

This project is designed strictly for cybersecurity education and defensive analysis.

It uses:

* Synthetic phishing emails
* Synthetic legitimate emails
* Reserved/example domains
* Reserved documentation IP addresses
* Static URL inspection
* Static attachment filename analysis

It does **not**:

* Send phishing emails
* Collect credentials
* Create credential-harvesting pages
* Attack real users, websites, or organizations
* Automatically visit suspicious URLs
* Execute suspicious attachments

---

## Problem Statement

Email-based social engineering remains an important cybersecurity challenge. A legitimate-looking message may contain subtle indicators such as:

* Suspicious sender patterns
* Urgent or threatening language
* Credential requests
* Financial pressure
* Suspicious URLs
* Raw IP-based links
* Excessive subdomains
* Suspicious attachment names
* Double file extensions
* Unusual formatting

Manual inspection can be time-consuming, especially when security teams receive many reported emails.

The purpose of this project is to provide a beginner-friendly defensive analysis platform that combines multiple indicators and explains why an email receives a particular risk assessment.

---

## Objectives

The project aims to:

1. Analyze email sender information.
2. Analyze subjects and email body content.
3. Detect urgency and social-engineering language.
4. Extract and analyze URLs without visiting them.
5. Inspect attachment filenames without executing files.
6. Engineer cybersecurity-focused email features.
7. Generate a rule-based phishing risk score.
8. Optionally use machine learning for classification.
9. Combine rule-based and ML signals using a hybrid detector.
10. Explain the reasons behind the assessment.
11. Store safe analysis metadata.
12. Present historical analytics through a dashboard.
13. Provide phishing-awareness education.
14. Demonstrate secure and defensive coding practices.

---

## Features

### Email Analyzer

Users can enter:

* Sender
* Subject
* Email body
* Optional URL
* Optional attachment filename

The system analyzes the input and produces:

* Risk score
* Classification
* Sender findings
* Content findings
* URL findings
* Attachment findings
* Explanation
* Security recommendations

### Safe `.txt` / `.eml` Upload

The frontend supports safe sample email files.

The parser:

* Reads text locally
* Extracts common `From` and `Subject` headers
* Identifies URLs
* Identifies attachment metadata where available
* Removes HTML tags before display
* Limits upload size
* Rejects unsupported file types

No uploaded attachment is executed.

### Static URL Analyzer

URLs are analyzed locally without opening or visiting the destination.

The analyzer checks characteristics such as:

* Scheme
* Hostname
* Path
* Query
* URL length
* Hostname length
* Subdomain count
* Raw IP addresses
* Suspicious URL keywords
* Shortener patterns
* Unusual characters
* HTTPS presence
* Potentially deceptive structure

HTTPS is treated as a feature, not proof that a destination is trustworthy.

### Sender Analyzer

Sender analysis checks for:

* Email formatting
* Domain characteristics
* Domain length
* Excessive subdomains
* Unusual characters
* Display-name mismatch
* Obvious synthetic lookalike patterns

An unfamiliar domain is not automatically considered malicious.

### Content Analyzer

The content engine looks for signals including:

* Urgency
* Fear or threats
* Financial pressure
* Credential requests
* Personal-information requests
* Reward or prize language
* Suspicious calls to action
* Generic greetings
* Language anomalies
* Unusual formatting

### Attachment Analyzer

Attachment analysis is metadata-only.

Potentially suspicious filename patterns include:

* `.exe`
* `.scr`
* `.bat`
* `.cmd`
* `.js`
* `.vbs`
* `.ps1`
* Suspicious archive types
* Double extensions such as `invoice.pdf.exe`

Attachments are never executed.

---

## Cybersecurity Relevance

The project demonstrates concepts relevant to:

* Email security
* Phishing detection
* Social engineering
* Security awareness
* Threat scoring
* SOC triage
* URL analysis
* Feature engineering
* Machine learning
* Explainable security decisions
* Secure software development
* Security analytics

The dashboard is intended to support analyst review rather than replace human judgment.

---

## Architecture

```text
                    ┌─────────────────────────┐
                    │       React Frontend    │
                    │ Dashboard / Analyzer    │
                    │ URL / Awareness/History │
                    └────────────┬────────────┘
                                 │
                                 │ REST API
                                 ▼
                    ┌─────────────────────────┐
                    │      FastAPI Backend    │
                    └────────────┬────────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            │                    │                    │
            ▼                    ▼                    ▼
    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
    │ Preprocessor │     │   Analysis   │     │   Database   │
    │              │     │   Services   │     │    SQLite    │
    └──────┬───────┘     └──────┬───────┘     └──────────────┘
           │                    │
           ▼                    ▼
    ┌──────────────┐     ┌───────────────────────────┐
    │   Features   │     │ Sender / Content / URL / │
    │ 18 Features  │     │ Attachment Analysis      │
    └──────┬───────┘     └─────────────┬─────────────┘
           │                           │
           ▼                           ▼
    ┌──────────────┐        ┌──────────────────────┐
    │ ML Pipeline  │        │   Rule-Based Engine  │
    │ TF-IDF + ML  │        │     Risk Scoring     │
    └──────┬───────┘        └──────────┬───────────┘
           │                           │
           └─────────────┬─────────────┘
                         ▼
                ┌────────────────────┐
                │  Hybrid Detector   │
                │ Rule + ML Signals  │
                └─────────┬──────────┘
                          ▼
                ┌────────────────────┐
                │ Explainable Result │
                │ Score + Findings   │
                │ + Recommendations  │
                └────────────────────┘
```

### Detection Workflow

```text
Email Input
    ↓
Preprocessing
    ↓
Sender Analysis
    ↓
Content Analysis
    ↓
URL Analysis
    ↓
Attachment Analysis
    ↓
Feature Extraction
    ↓
Rule-Based Detection
    ↓
Machine Learning Detection
    ↓
Hybrid Detection
    ↓
Risk Score
    ↓
Classification
    ↓
Explainability
    ↓
Security Recommendations
    ↓
History + Dashboard Analytics
```

---

## Technology Stack

### Backend

* Python
* FastAPI
* Pydantic
* SQLite
* Uvicorn
* scikit-learn
* joblib

### Frontend

* React
* Vite
* JavaScript
* CSS

### Machine Learning

* TF-IDF
* Logistic Regression
* Naive Bayes
* Random Forest
* Precision
* Recall
* F1-score
* Confusion matrix

### Development

* VS Code
* Git
* GitHub
* Python virtual environment

---

## Project Structure

```text
Phishing-Email-Detection-Awareness-Dashboard/
│
├── backend/
│   ├── app.py
│   ├── database.py
│   ├── schemas.py
│   │
│   ├── models/
│   │   └── __init__.py
│   │
│   ├── routes/
│   │   ├── __init__.py
│   │   └── api.py
│   │
│   └── services/
│       ├── analysis_service.py
│       ├── attachment_analyzer.py
│       ├── content_analyzer.py
│       ├── explainability.py
│       ├── feature_engineering.py
│       ├── history_service.py
│       ├── hybrid_detector.py
│       ├── preprocessor.py
│       ├── risk_engine.py
│       ├── sender_analyzer.py
│       └── url_analyzer.py
│
├── data/
│   ├── generate_dataset.py
│   ├── preprocess_dataset.py
│   ├── extract_features.py
│   ├── phishing_email_dataset.csv
│   └── processed_phishing_email_dataset.csv
│
├── docs/
│   ├── ARCHITECTURE.md
│   └── FEATURE_DICTIONARY.md
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── ...
│
├── ml/
│   ├── train_model.py
│   ├── evaluation.py
│   ├── confusion_matrix.py
│   └── predict.py
│
├── models/
│   └── trained model artifacts
│
├── tests/
│   ├── test_database.py
│   ├── test_api.py
│   ├── test_ml.py
│   └── ...
│
├── README.md
├── .gitignore
└── requirements.txt
```

---

## Dataset

The dataset is programmatically generated for defensive and educational use.

### Dataset Characteristics

The project generates **600 synthetic email records** containing legitimate and phishing-style examples.

The dataset schema is:

```text
email_id
sender
sender_domain
subject
body
urls
attachment_name
label
```

Labels:

```text
LEGITIMATE
PHISHING
```

### Legitimate Categories

Examples include:

* University notices
* HR updates
* Project updates
* Meeting reminders
* Shopping confirmations
* Newsletters
* Password-change confirmations
* Fictional bank-style notifications

### Phishing Categories

Examples include:

* Fake account verification
* Fake invoice
* Fake prize
* Fake password expiration
* Fake delivery notification
* Fake HR request
* Fake executive request

The dataset uses fictional/example domains and safe demonstration data.

---

## Feature Engineering

The required phishing feature set contains 18 security-oriented features:

```text
urgent_keyword_count
credential_keyword_count
financial_keyword_count
threat_keyword_count
url_count
suspicious_url_count
has_ip_url
has_shortened_url_pattern
sender_domain_length
subdomain_count
suspicious_attachment
generic_greeting
contains_password_request
contains_personal_info_request
exclamation_count
uppercase_ratio
body_length
subject_length
```

These features preserve useful cybersecurity signals instead of performing aggressive text cleaning that could remove evidence.

---

## Sender Analysis

The sender engine evaluates sender-related indicators.

Examples:

* Invalid email structure
* Suspicious domain characteristics
* Excessive subdomains
* Unusual characters
* Display-name mismatch
* Obvious synthetic lookalike patterns

The output includes:

```text
sender_risk_score
sender_findings[]
```

An unfamiliar sender domain alone does not prove phishing.

---

## Email Content Analysis

Content analysis searches for contextual signals associated with social engineering.

The engine can identify:

* Urgency
* Threats
* Fear
* Credential requests
* Financial pressure
* Requests for personal information
* Rewards and prizes
* Suspicious calls to action
* Generic greetings
* Language anomalies
* Unusual formatting

Each finding is intended to be explainable to the user.

---

## URL Analysis

The URL analyzer is completely static.

It does not:

* Open URLs
* Resolve suspicious destinations
* Download content
* Execute scripts
* Contact suspicious websites automatically

Example URL characteristics:

```text
Scheme
Hostname
Path
Query
URL length
Hostname length
Subdomain count
Raw IP
Suspicious keywords
Shortener pattern
Unusual characters
HTTPS presence
Potential deceptive structure
```

A URL is evaluated from its structure and text rather than from live browsing.

---

## Attachment Analysis

Attachment analysis uses filenames only.

Example:

```text
invoice.pdf.exe
```

This may be flagged as suspicious because of the double extension and executable extension.

The system never opens or executes the attachment.

---

## Risk Scoring

The rule engine combines multiple indicators.

Current project assumptions:

| Indicator             | Weight |
| --------------------- | -----: |
| Suspicious sender     |    +15 |
| Urgency               |    +10 |
| Credential request    |    +20 |
| Suspicious URL        |    +20 |
| Suspicious attachment |    +25 |
| Generic greeting      |     +5 |
| Threat/Fear language  |    +10 |

The final rule score is capped between `0` and `100`.

### Classification Thresholds

|  Score | Classification              |
| -----: | --------------------------- |
|   0–20 | LOW RISK                    |
|  21–40 | MODERATE RISK               |
|  41–70 | SUSPICIOUS                  |
| 71–100 | HIGH RISK / LIKELY PHISHING |

These thresholds are project-level assumptions and should be calibrated against validation data for production use.

---

## Machine Learning

The ML pipeline provides an additional classification signal.

Implemented approaches include:

* TF-IDF text representation
* Logistic Regression
* Naive Bayes
* Random Forest

The dataset is divided into:

```text
Training
Validation
Test
```

Model selection is based on validation performance rather than simply choosing a model arbitrarily.

Evaluation includes:

* Accuracy
* Precision
* Recall
* F1-score
* Confusion matrix

Actual model metrics should be taken from the generated training/evaluation output instead of being hard-coded in this README.

---

## Hybrid Detection

The project combines rule-based detection and ML probability.

Current project assumption:

```text
Rule Engine Weight = 60%
ML Weight          = 40%
```

Conceptually:

```text
Hybrid Score
    =
0.60 × Rule Signal
+
0.40 × ML Signal
```

The ML probability is treated as a supporting signal, not absolute certainty.

The hybrid approach helps combine:

* Human-readable cybersecurity rules
* Statistical text patterns
* Explainability
* Machine-learning classification

---

## Explainable Detection

The result is designed to answer:

```text
What is the risk?
Why was the email flagged?
Which indicators were detected?
What should the user do?
```

The output can contain:

* Risk score
* Classification
* Findings
* Detection reasons
* Security recommendations
* Privacy/safety notes

Explainability is important because a security user should understand why an automated system produced an assessment.

---

## Dashboard

The dashboard includes analytics such as:

* Total analyses
* Likely phishing
* Suspicious analyses
* Low-risk analyses
* Average risk
* Classification distribution
* Risk-score distribution
* Risk trend
* Top indicators
* Analysis history

The dashboard is designed to resemble a small defensive security-analysis interface rather than a simple prediction script.

---

## Security Awareness

The awareness module provides user education through sections such as:

### How to Spot a Phishing Email

Users are taught to inspect:

* Sender details
* Subject wording
* Urgency
* Requests for credentials
* Financial pressure
* Suspicious URLs
* Attachments
* Unexpected requests

### Before You Click

The application reinforces safe behaviors such as:

* Stop and inspect the message
* Verify the sender
* Check the destination independently
* Avoid entering credentials through unexpected links
* Treat urgent requests carefully
* Report suspicious messages through authorized channels

---

## API Documentation

The FastAPI backend exposes the following endpoints:

| Method | Endpoint                    | Purpose                       |
| ------ | --------------------------- | ----------------------------- |
| POST   | `/api/analyze`              | Analyze an email              |
| POST   | `/api/analyze/url`          | Analyze a URL statically      |
| GET    | `/api/analyses`             | Retrieve analysis history     |
| GET    | `/api/analyses/{id}`        | Retrieve a specific analysis  |
| GET    | `/api/dashboard/stats`      | Retrieve dashboard statistics |
| GET    | `/api/dashboard/indicators` | Retrieve indicator analytics  |
| DELETE | `/api/analyses/{id}`        | Delete an analysis            |

FastAPI documentation can be viewed from the local backend when the server is running.

Typical local documentation paths are:

```text
http://127.0.0.1:8000/docs
http://127.0.0.1:8000/redoc
```

---

## Database

SQLite is used for local persistence.

Core tables include:

```text
analyses
indicators
url_analyses
```

The database stores safe analysis metadata and structured findings.

The application is designed to avoid unnecessarily storing sensitive raw email content.

---

## Installation

### 1. Clone the Repository

```powershell
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd Phishing-Email-Detection-Awareness-Dashboard
```

### 2. Create a Python Virtual Environment

```powershell
py -3 -m venv .venv
```

### 3. Activate the Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install Python Dependencies

```powershell
python -m pip install -r requirements.txt
```

### 5. Generate the Synthetic Dataset

```powershell
python data/generate_dataset.py
```

### 6. Preprocess the Dataset

```powershell
python data/preprocess_dataset.py
```

### 7. Extract Features

```powershell
python data/extract_features.py
```

### 8. Train the ML Model

```powershell
python ml/train_model.py
```

### 9. Start the FastAPI Backend

```powershell
uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

### 10. Start the Frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite development URL shown in the terminal.

---

## Usage

### Safe Phishing Demonstration

Use only the synthetic sample defined for the project.

```text
Sender:
security-alert@account-check.invalid.test

Subject:
URGENT: Verify Your Account Immediately

URL:
http://198.51.100.10/verify-account
```

Potential indicators include:

* Urgency
* Credential/account-verification request
* Suspicious sender pattern
* Raw IP URL
* Non-HTTPS URL

The project specification defines this as a synthetic high-risk demonstration.

### Safe Legitimate Demonstration

```text
Sender:
training@example.org

Subject:
Cybersecurity Workshop Reminder
```

The message should contain normal informational content without credential requests or suspicious indicators.

The classification should be interpreted from the actual analysis result rather than assumed solely from the sample category.

---

## Testing

The project contains automated tests for major components.

Run the complete test suite with:

```powershell
pytest -q
```

Run Python compilation checks:

```powershell
python -m compileall backend ml tests
```

Run package validation:

```powershell
python -m pip check
```

Build the frontend:

```powershell
cd frontend
npm run build
cd ..
```

### Core Test Areas

Testing covers scenarios such as:

* Legitimate email
* Urgent phishing-style email
* Credential requests
* Financial requests
* Generic greetings
* Safe URLs
* Raw IP URLs
* Non-HTTPS URLs
* Excessive subdomains
* Suspicious URL keywords
* Multiple URLs
* Normal attachments
* Executable attachment filenames
* Double extensions
* Empty fields
* Invalid sender format
* Uppercase-heavy messages
* Multiple exclamation marks
* Risk-score boundaries
* Database persistence
* API validation
* ML prediction
* Analysis-history retrieval

---

## Security & Privacy

The project follows defensive security principles.

### Attachment Safety

Attachments are inspected by filename and metadata only.

They are never executed.

### URL Safety

Suspicious URLs are analyzed statically.

The dashboard does not automatically visit them.

### Input Validation

The application validates user-provided input and file types.

### Upload Limits

Uploaded `.txt` and `.eml` content is limited to a safe file size.

### XSS Protection

Raw email HTML should not be rendered directly because email HTML can contain unsafe content.

The frontend strips HTML before displaying uploaded text content.

### Privacy

The project is designed to avoid unnecessary storage of raw email bodies or sensitive information.

### Secrets

Sensitive values should be stored in environment variables rather than committed to GitHub.

### Production Security

A production deployment should additionally use:

* HTTPS
* Authentication
* Authorization
* Rate limiting
* Secure logging
* Strong secret management
* Centralized monitoring

---

## False Positives & False Negatives

No phishing detector is perfect.

### False Positive

A legitimate email may contain strong urgency.

Example:

```text
Urgent: Submit your university documents today.
```

An urgency rule may increase the score even though the message is legitimate.

### False Negative

A carefully written phishing email may:

* Use normal grammar
* Avoid obvious urgency
* Avoid suspicious attachments
* Use realistic wording
* Contain few obvious indicators

This is why multiple signals should be considered together and automated analysis should support human review.

---

## SOC Analyst Workflow

The dashboard can support a simplified defensive SOC-style workflow:

```text
Email Reported
      ↓
Initial Triage
      ↓
Sender Analysis
      ↓
URL Analysis
      ↓
Attachment Metadata Analysis
      ↓
Content Analysis
      ↓
Risk Score
      ↓
Analyst Review
      ↓
Classification
      ↓
Recommended Response
```

The application is an educational demonstration of this workflow, not a replacement for a full enterprise SOC platform.

---

## MITRE ATT&CK Context

Phishing is represented in the MITRE ATT&CK knowledge base under social-engineering techniques.

Relevant concepts include:

* Spearphishing Attachment
* Spearphishing Link
* Spearphishing via Service

Framework mapping can make security documentation easier to understand and can help connect individual detections with broader defensive workflows.

Technique identifiers should always be checked against the current official MITRE ATT&CK documentation before being used in production documentation.

---

## Results

The project produces structured outputs including:

```text
Risk Score
Classification
Rule-Based Findings
Sender Findings
Content Findings
URL Findings
Attachment Findings
ML Prediction
Hybrid Assessment
Recommendations
```

Training and evaluation metrics are generated by the ML pipeline.

The project does not hard-code performance claims in this README. This avoids presenting unverified metrics as measured results.

---

## Limitations

Current limitations include:

* Synthetic dataset rather than a production-scale mail corpus
* Static URL analysis only
* No live reputation lookups
* No live domain intelligence
* Filename-based attachment analysis
* Limited email-header analysis
* No production SIEM integration
* No enterprise authentication workflow
* No real-world mailbox ingestion
* ML performance depends on the training dataset

The system should therefore be treated as a defensive educational prototype.

---

## Future Improvements

Possible defensive improvements include:

* Email-header analysis
* SPF/DKIM/DMARC result ingestion
* Domain reputation integration
* URL reputation APIs
* Attachment hash reputation
* Advanced NLP models
* Explainable AI techniques
* User reporting workflows
* SOC ticket integration
* SIEM integration
* Threat-intelligence enrichment
* Security-awareness quizzes
* Feedback-based model retraining

Any future implementation should remain defensive and use authorized data.

---

## Screenshots

Recommended screenshot names:

```text
01_project_structure.png
02_architecture_diagram.png
03_synthetic_dataset.png
04_dataset_statistics.png
05_email_analyzer.png
06_legitimate_email_analysis.png
07_phishing_email_analysis.png
08_sender_risk_findings.png
09_url_risk_analysis.png
10_attachment_analysis.png
11_phishing_risk_score.png
12_explainable_findings.png
13_security_recommendations.png
14_dashboard_overview.png
15_classification_distribution.png
16_risk_distribution.png
17_top_phishing_indicators.png
18_ml_metrics.png
19_confusion_matrix.png
20_analysis_history.png
21_awareness_module.png
22_automated_tests.png
23_api_response.png
24_github_commits.png
25_github_repository.png
26_readme_preview.png
```

These screenshots provide visual evidence of the application's functionality and development history.

---

## Learning Outcomes

This project demonstrates practical experience with:

* Python development
* FastAPI REST APIs
* React/Vite frontend development
* SQLite persistence
* Synthetic dataset generation
* Text preprocessing
* Feature engineering
* Rule-based cybersecurity detection
* URL analysis
* Sender analysis
* Attachment metadata inspection
* Machine learning
* Model evaluation
* Hybrid detection
* Explainable security decisions
* Data visualization
* Security awareness
* Automated testing
* Secure coding practices
* Git and GitHub workflows

---

## GitHub Development History

Recommended milestone commits include:

```text
Initialize phishing detection project
Add synthetic email dataset generator
Implement email preprocessing
Add sender analysis module
Implement phishing content analyzer
Add static URL risk analysis
Implement attachment filename analysis
Build phishing risk scoring engine
Add optional ML detection model
Implement model evaluation
Build cybersecurity dashboard
Add phishing awareness module
Implement analysis history
Add automated security tests
Complete README and documentation
```

---

## Git Commands

After saving this README:

```powershell
git status
git add README.md
git commit -m "Complete README and documentation"
git push origin main
```

Check the latest commit:

```powershell
git log --oneline -5
```

---

## Project Disclaimer

> This project is designed for cybersecurity education and defensive analysis using synthetic or authorized data.

Do not use the project to send phishing emails, harvest credentials, attack real systems, execute suspicious attachments, or automatically visit suspicious URLs.

---

## Author

**Ayush Kumar Dubey**

Cybersecurity | Python | Machine Learning | Email Security | Security Analytics

**Repository:** `Phishing-Email-Detection-Awareness-Dashboard`
