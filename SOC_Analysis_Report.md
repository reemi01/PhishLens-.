# PhishLens — SOC Analysis Report

## 1. Executive Summary

PhishLens is a Python-based phishing screening tool designed to support the initial triage of suspicious email messages and URLs.

The application identifies configured phishing-related keywords, extracts and inspects URLs for selected warning patterns, calculates a rule-based risk score, and optionally retrieves existing URL analysis reports from VirusTotal. It also records incidents, provides a basic SOC dashboard, and supports JSON and CSV report exports.

**Project Type:** Security Operations Center (SOC) — Phishing Triage  
**Project Status:** Learning Prototype  
**Analysis Method:** Rule-based detection with optional threat-intelligence enrichment  
**Technology Stack:** Python, Streamlit, VirusTotal API

## 2. Project Objectives

- Identify configured phishing-related language in email messages.
- Extract HTTP and HTTPS URLs for inspection.
- Detect selected URL warning patterns.
- Calculate a preliminary risk score using configurable scoring rules.
- Enrich URL analysis with existing VirusTotal reports when enabled.
- Generate structured JSON reports.
- Record incidents in a local JSON Lines log.
- Provide incident filtering, CSV export, and basic SOC dashboard statistics.

## 3. Detection Methodology

### 3.1 Email Indicators

PhishLens checks messages for configured phrases, including:

- Verify your password
- Account will be suspended
- Urgent
- Click here
- Confirm your account

These phrases may indicate social engineering attempts. However, their presence alone does not prove that a message is malicious.

### 3.2 URL Extraction and Local Analysis

The application extracts explicit HTTP and HTTPS URLs and checks them for selected warning patterns:

- IP addresses used as hostnames.
- HTTP instead of HTTPS.
- An `@` symbol in the URL authority.
- Known URL-shortening services.
- Selected internationalized-domain patterns.
- Unusually deep subdomain structures.

These checks are heuristic indicators. A warning does not independently establish that a URL is malicious, and the absence of warnings does not establish that it is safe.

PhishLens does not open extracted URLs or submit them for scanning.

### 3.3 VirusTotal Threat Intelligence

When enabled and configured with an API key, PhishLens retrieves existing URL reports through the VirusTotal API.

The application displays available malicious, suspicious, harmless, and undetected detection counts. If VirusTotal reports malicious or suspicious detections, these results may raise the final risk score.

The integration retrieves existing reports only; it does not submit URLs for a new scan. A missing report or a report with no malicious detections is not proof that a URL is safe.

## 4. Risk Scoring and Classification

PhishLens uses a rule-based scoring model implemented in `risk_engine.py`.

### Local Risk Score

- Unique message indicators contribute 20 points each, up to a maximum of 60 points.
- Unique URL warnings contribute 15 points each, up to a maximum of 40 points.
- The local score is capped at 100.

| Score | Classification |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–100 | HIGH |

Duplicate indicators and URL warnings are counted only once within their respective categories.

### Final Risk Assessment

The application combines the local score with available VirusTotal findings:

- If one or more malicious detections are reported, the final score is raised to at least 85.
- Otherwise, if one or more suspicious detections are reported, the final score is raised to at least 60.
- Otherwise, the local score is retained.

The final score is capped indirectly by the local score and these minimum thresholds, which do not exceed 100.

These thresholds are prototype rules. They are not a validated probability of phishing, and the scoring model has not been established as a substitute for professional security analysis.

## 5. Example Investigation

**Scenario:** A message contains a URL using HTTP and an IP address as its hostname.

**Example URL:** `http://192.0.2.10/login`

Expected local URL findings:

- URL uses an IP address.
- URL does not use HTTPS.

The IP address is from a range reserved for documentation and is used only as a demonstration example.

With two unique URL warnings and no message indicators, the local scoring model produces:

- Message risk points: 0
- URL risk points: 30
- Local risk score: 30/100
- Local risk classification: MEDIUM

If VirusTotal is not enabled, or no relevant detections are available, the final score remains 30. If usable VirusTotal findings are returned, the final assessment may be higher according to the configured rules.

## 6. Incident Logging and SOC Dashboard

When configured phishing indicators or URL warnings are detected, PhishLens creates an incident identifier and attempts to append a record to `incident_log.jsonl`.

The incident log stores fields such as:

- Incident ID and incident type.
- Analysis timestamp.
- Final risk score and classification.
- Local risk score.
- Available VirusTotal malicious and suspicious detection counts.
- Counts of message indicators and extracted URLs.

The application also provides:

- Filtering by risk level and incident type.
- CSV export of recorded incident entries.
- Downloadable JSON analysis reports.
- Dashboard statistics for total incidents, risk-level distribution, and average recorded risk score.

Incident records are stored locally. The prototype does not provide centralized logging, access control, or a production-grade case-management workflow.

## 7. Analyst Recommendations

For a real suspicious email, an analyst should:

1. Avoid clicking links or opening unexpected attachments.
2. Verify the sender using an independent, trusted channel.
3. Review email headers and authentication results when available.
4. Preserve the original message and relevant evidence.
5. Follow the organization's phishing-reporting and incident-response procedures.
6. Escalate the case according to organizational policy.

PhishLens findings should support, rather than replace, analyst judgment.

## 8. Testing and Validation

The project includes unit tests in `test_phishlens.py` for the rule-based risk engine, including:

- Empty input.
- A single message indicator.
- Multiple URL warnings.
- Combined message and URL indicators.
- Score limits.
- Duplicate indicator handling.

The tests should be executed using:

`python -m unittest discover -v`

Record the actual test result before publishing this report. Additional testing is recommended for URL extraction, URL parsing, VirusTotal response handling, incident logging, and report exports.

## 9. Limitations

- Detection relies on a small, manually configured set of rules.
- Legitimate messages may trigger warnings, and malicious messages may evade detection.
- HTTPS does not guarantee that a website is trustworthy.
- URL extraction focuses on explicit HTTP and HTTPS links.
- The score is a heuristic, not a machine-learning prediction or calibrated probability.
- VirusTotal results depend on the availability and coverage of existing reports.
- The prototype does not perform sandboxing, attachment analysis, email-header analysis, or comprehensive domain reputation checks.
- Incident data is stored locally rather than in a centralized security platform.
- The application has not been validated as a production security control.

## 10. Future Improvements

- Expand automated unit and integration tests.
- Improve URL parsing and domain validation.
- Support configurable detection rules.
- Add email-header and authentication analysis.
- Integrate additional trusted threat-intelligence sources.
- Improve incident management and audit logging.
- Add richer report exports and dashboard visualizations.
- Evaluate detection quality using a documented test dataset.
- Add deployment guidance and secure configuration documentation.

## 11. Conclusion

PhishLens demonstrates foundational phishing-triage concepts relevant to junior SOC analyst workflows, including indicator identification, URL inspection, heuristic risk classification, optional threat-intelligence enrichment, incident documentation, and analyst recommendations.

The project is a learning prototype. Its results should be treated as preliminary indicators and should not be used as the sole basis for real-world security decisions.
