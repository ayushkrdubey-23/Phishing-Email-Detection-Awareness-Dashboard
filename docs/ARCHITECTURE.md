
# Phishing Email Detection & Awareness Dashboard
## System Architecture Documentation

### 1. Project Overview

The Phishing Email Detection & Awareness Dashboard is a defensive cybersecurity application designed to analyze email content and identify potential phishing indicators.

The application uses static analysis, rule-based detection, feature engineering, and optional machine learning to generate explainable phishing risk assessments.

The project uses synthetic, fictional, or authorized email samples.

### 2. System Architecture

The application follows a modular client-server architecture.

Main components:

1. React Frontend
2. FastAPI Backend
3. Email Preprocessing
4. Sender Analysis Engine
5. Email Content Analysis Engine
6. URL Analysis Engine
7. Attachment Analysis Engine
8. Feature Engineering
9. Rule-Based Detection Engine
10. Optional Machine Learning Engine
11. Explainability and Recommendation Engine
12. SQLite Database

### 3. Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Backend | FastAPI |
| Frontend | React.js |
| Build Tool | Vite |
| Styling | CSS |
| Data Processing | Pandas |
| Machine Learning | Scikit-learn |
| Text Processing | TF-IDF |
| Database | SQLite |
| Visualization | Recharts |
| API Documentation | Swagger UI |
| Testing | Pytest |
| Version Control | Git |

### 4. Component Responsibilities

#### 4.1 Frontend

The frontend provides:

- Email input form
- Sender information input
- Subject input
- Email body input
- Optional attachment filename input
- Analysis results
- Risk indicators
- Analytics dashboard
- Analysis history
- Security awareness module

#### 4.2 Backend

FastAPI handles:

- API requests
- Input validation
- Application services
- Detection engine integration
- Database operations
- API responses
- Error handling

#### 4.3 Sender Analyzer

Examines:

- Sender email format
- Sender domain
- Domain length
- Subdomain count
- Unusual characters
- Display-name mismatch
- Possible lookalike patterns

#### 4.4 Content Analyzer

Identifies:

- Urgency
- Fear and threats
- Financial pressure
- Credential requests
- Personal information requests
- Reward claims
- Generic greetings

#### 4.5 URL Analyzer

Performs static URL analysis without opening suspicious links.

Examines:

- URL scheme
- Hostname
- URL length
- Raw IP usage
- Subdomain count
- Suspicious keywords
- Shortener patterns
- Unusual characters
- HTTPS presence

#### 4.6 Attachment Analyzer

Performs filename-only analysis.

Detects:

- Executable extensions
- Script extensions
- Suspicious archive extensions
- Double extensions

No attachment will be executed.

#### 4.7 Risk Engine

Combines detection findings and calculates a risk score between 0 and 100.

The engine generates:

- Risk score
- Classification
- Detected indicators
- Explanations
- Recommended actions

#### 4.8 Machine Learning Module

The optional ML module uses:

- TF-IDF
- Logistic Regression
- Naive Bayes
- Random Forest

Models will be evaluated using actual test results.

#### 4.9 Database

SQLite stores safe analysis metadata, including:

- Analysis ID
- Sender domain
- Subject
- Risk score
- Classification
- Indicators
- Analysis timestamp

Raw email bodies will not be stored by default.

### 5. Complete Data Flow

1. User enters email information.
2. React sends an API request.
3. FastAPI validates the request.
4. Preprocessing extracts relevant information.
5. Sender analysis runs.
6. Content analysis runs.
7. URL analysis runs.
8. Attachment analysis runs.
9. Feature engineering creates structured features.
10. Rule-based detection calculates the risk score.
11. Optional ML detection generates a prediction.
12. Hybrid detection combines the outputs when enabled.
13. Explainability generates findings.
14. Recommendation engine generates security advice.
15. SQLite stores analysis metadata.
16. React displays the results.

### 6. Security Boundaries

The application follows these security principles:

- Use only synthetic or authorized email samples.
- Never send phishing emails.
- Never collect credentials.
- Never create credential-harvesting pages.
- Never automatically visit suspicious URLs.
- Never execute uploaded attachments.
- Analyze URL strings statically.
- Validate uploaded file types.
- Restrict upload size.
- Avoid unnecessary storage of email content.
- Escape user-provided content before rendering.
- Keep application secrets in environment variables.

### 7. Database Design

The application will contain three primary tables:

#### ANALYSES

Stores the main analysis record.

#### INDICATORS

Stores individual findings associated with an analysis.

#### URL_ANALYSES

Stores static URL analysis results associated with an analysis.

Relationships:

- One analysis can contain multiple indicators.
- One analysis can contain multiple URL analysis records.

### 8. Deployment Architecture

Initial deployment will be local.

Frontend:
React + Vite

Backend:
FastAPI

Database:
SQLite

Machine Learning:
Locally stored trained model

The project will not require paid cybersecurity services.

### 9. Important Limitations

- A suspicious indicator does not automatically prove phishing.
- HTTPS does not guarantee website trustworthiness.
- Unfamiliar sender domains are not automatically malicious.
- ML predictions are not guaranteed to be correct.
- Risk thresholds are project assumptions requiring validation.
- Automated analysis supports human judgment rather than replacing it.

### 10. Project Objective

To build an explainable, modular, beginner-friendly, and industry-oriented defensive cybersecurity application that demonstrates email security, phishing detection, machine learning, threat scoring, security analytics, and awareness training.

---

**Author:** Ayush Kumar Dubey

**Project:** Phishing Email Detection & Awareness Dashboard

**Purpose:** Cybersecurity Education and Defensive Security Analysis