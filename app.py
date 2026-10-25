
import streamlit as st
import re
import ipaddress
import json
import uuid
import csv
import io
import base64
import os
from pathlib import Path
from datetime import datetime
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv

from risk_engine import calculate_risk

# -----------------------------------
# Configuration
# -----------------------------------
load_dotenv()

LOG_PATH = Path("incident_log.jsonl")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls"

st.set_page_config(
    page_title="PhishLens | Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------
# Professional UI
# -----------------------------------
st.markdown("""
<style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1400px;
    }

    .hero {
        padding: 1.8rem 2rem;
        border: 1px solid rgba(100, 160, 255, 0.25);
        border-radius: 18px;
        background: linear-gradient(135deg, #14243a, #10141e);
        margin-bottom: 1.5rem;
    }

    .hero-title {
        font-size: 2.7rem;
        font-weight: 800;
        margin-bottom: 0.3rem;
        color: #f4f7ff;
    }

    .hero-subtitle {
        font-size: 1.1rem;
        color: #a9c7f5;
        margin-bottom: 0.8rem;
    }

    .hero-description {
        color: #d1d9e6;
        margin-bottom: 0;
    }

    div[data-testid="stMetric"] {
        background: rgba(40, 55, 78, 0.45);
        border: 1px solid rgba(150, 175, 210, 0.2);
        padding: 1rem;
        border-radius: 14px;
    }

    div.stButton > button,
    div.stDownloadButton > button {
        border-radius: 10px;
        font-weight: 600;
        min-height: 2.8rem;
    }

    div[data-testid="stAlert"] {
        border-radius: 12px;
    }

    h2, h3 {
        letter-spacing: -0.3px;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
    <div class="hero-title">🛡️ PhishLens</div>
    <div class="hero-subtitle">Phishing Detection &amp; URL Analysis</div>
    <p class="hero-description">
        A security triage tool for suspicious messages, URL indicators,
        and VirusTotal threat intelligence.
    </p>
</div>
""", unsafe_allow_html=True)

st.info(
    "⚠️ Results are risk indicators, not proof that a message is malicious or safe."
)

# -----------------------------------
# 1. Incident history
# -----------------------------------
def load_incidents():
    incidents = []

    if LOG_PATH.exists():
        try:
            with LOG_PATH.open("r", encoding="utf-8") as file:
                for line in file:
                    if not line.strip():
                        continue
                    try:
                        incidents.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            st.warning("Could not read the incident log.")

    return incidents


# -----------------------------------
# 2. Incident classification
# -----------------------------------
def classify_incident(found_words, url_analysis):
    credential_terms = {
        "verify your password",
        "confirm your account",
    }

    if any(word in credential_terms for word in found_words):
        return "Credential Theft"

    if any(item["warnings"] for item in url_analysis):
        return "Suspicious URL"

    if found_words:
        return "Phishing Indicators"

    return "Unclassified"


# -----------------------------------
# 3. VirusTotal API
# -----------------------------------
def check_virustotal_url(url, api_key):
    """Retrieve an existing URL report without submitting a new scan."""

    if not api_key:
        return {
            "status": "not_configured",
            "message": "VirusTotal API key is not configured.",
        }

    url_id = (
        base64.urlsafe_b64encode(url.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )

    endpoint = f"{VIRUSTOTAL_URL_API}/{url_id}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15,
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": "No existing VirusTotal report was found.",
                "report_url": (
                    f"https://www.virustotal.com/gui/url/{url_id}"
                ),
            }

        if response.status_code == 401:
            return {
                "status": "error",
                "message": (
                    "VirusTotal rejected the API key. "
                    "Check your .env file."
                ),
            }

        if response.status_code == 429:
            return {
                "status": "rate_limited",
                "message": (
                    "VirusTotal API rate limit reached. Try again later."
                ),
            }

        response.raise_for_status()

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "found",
            "message": "Existing VirusTotal report retrieved.",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "report_url": (
                f"https://www.virustotal.com/gui/url/{url_id}"
            ),
        }

    except requests.Timeout:
        return {
            "status": "error",
            "message": "VirusTotal request timed out.",
        }

    except requests.RequestException:
        return {
            "status": "error",
            "message": "Could not contact VirusTotal. Check your connection.",
        }

    except (ValueError, TypeError):
        return {
            "status": "error",
            "message": "Unexpected response from VirusTotal.",
        }


# -----------------------------------
# 4. Message input
# -----------------------------------
st.subheader("🔎 Message Analyzer")
st.write(
    "Paste a suspicious email or message below to inspect its indicators."
)

with st.form("analysis_form"):
    email_text = st.text_area(
        "Email or message",
        height=200,
        placeholder=(
            "Example: Urgent! Verify your password "
            "at http://192.0.2.10/login"
        ),
    )

    use_virustotal = st.checkbox(
        "Check URLs against existing VirusTotal reports",
        value=False,
        help=(
            "Retrieves existing reports only. "
            "PhishLens does not submit URLs for scanning."
        ),
    )

    analyze_clicked = st.form_submit_button(
        "🔍 Analyze Message",
        type="primary",
        use_container_width=True,
    )

if use_virustotal and not VIRUSTOTAL_API_KEY:
    st.warning(
        "VirusTotal API key not found. Check your .env file "
        "and restart Streamlit."
    )

# -----------------------------------
# 5. Analyze message
# -----------------------------------
if analyze_clicked:

    if not email_text.strip():
        st.warning("Please enter a message first.")

    else:
        analysis_time = datetime.now().astimezone().isoformat()

        suspicious_words = [
            "verify your password",
            "account will be suspended",
            "urgent",
            "click here",
            "confirm your account",
        ]

        message_lower = email_text.lower()

        found_words = [
            word for word in suspicious_words
            if word in message_lower
        ]

        # Extract URLs
        urls = re.findall(
            r"""https?://[^\s<>"']+""",
            email_text,
            flags=re.IGNORECASE,
        )

        urls = list(dict.fromkeys(
            url.rstrip(".,!?;:)]}")
            for url in urls
        ))

        # Local URL analysis
        shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "is.gd",
            "ow.ly",
        ]

        url_analysis = []

        for url in urls:
            findings = []
            hostname = None

            try:
                parsed = urlsplit(url)
                hostname = parsed.hostname

                if not hostname:
                    findings.append("Invalid URL")

                else:
                    hostname = hostname.lower()

                    try:
                        ipaddress.ip_address(hostname)
                        findings.append("URL uses an IP address")
                    except ValueError:
                        pass

                    if parsed.scheme.lower() == "http":
                        findings.append("URL does not use HTTPS")

                    if "@" in parsed.netloc:
                        findings.append("URL contains an @ symbol")

                    if hostname in shorteners:
                        findings.append(
                            "URL uses a known link shortener"
                        )

                    if (
                        hostname.startswith("xn--")
                        or ".xn--" in hostname
                    ):
                        findings.append(
                            "Possible internationalized domain pattern"
                        )

                    if hostname.count(".") >= 3:
                        findings.append(
                            "Unusually deep subdomain structure"
                        )

            except ValueError:
                findings.append("Could not parse URL")

            url_analysis.append({
                "url": url,
                "hostname": hostname,
                "warnings": findings,
            })

        # VirusTotal lookups
        virustotal_results = []

        if use_virustotal and VIRUSTOTAL_API_KEY:
            for url in urls:
                result = check_virustotal_url(
                    url,
                    VIRUSTOTAL_API_KEY,
                )
                result["url"] = url
                virustotal_results.append(result)

        # Local risk score
        all_url_warnings = [
            warning
            for item in url_analysis
            for warning in item["warnings"]
        ]

        risk_result = calculate_risk(
            found_words,
            all_url_warnings,
        )

        local_risk_score = risk_result["risk_score"]
        local_risk_level = risk_result["risk_level"]
        message_points = risk_result["message_points"]
        url_points = risk_result["url_points"]

        # Combined risk assessment
        vt_malicious = sum(
            result.get("malicious", 0)
            for result in virustotal_results
            if result.get("status") == "found"
        )

        vt_suspicious = sum(
            result.get("suspicious", 0)
            for result in virustotal_results
            if result.get("status") == "found"
        )

        # External results may raise, but never lower, the local score.
        risk_score = local_risk_score

        final_risk_reasons = [
            (
                f"Local rule-based score: {local_risk_score}/100 "
                f"({local_risk_level})."
            )
        ]

        if vt_malicious > 0:
            risk_score = max(risk_score, 85)
            final_risk_reasons.append(
                f"VirusTotal reported {vt_malicious} "
                "malicious detection(s)."
            )

        elif vt_suspicious > 0:
            risk_score = max(risk_score, 60)
            final_risk_reasons.append(
                f"VirusTotal reported {vt_suspicious} "
                "suspicious detection(s)."
            )

        elif any(
            result.get("status") == "found"
            for result in virustotal_results
        ):
            final_risk_reasons.append(
                "VirusTotal returned a report without malicious "
                "or suspicious detections. This does not prove "
                "the URL is safe, so the local score is not reduced."
            )

        elif use_virustotal:
            final_risk_reasons.append(
                "No usable VirusTotal detection result was available. "
                "The local score is retained."
            )

        if risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        incident_type = classify_incident(
            found_words,
            url_analysis,
        )

        is_incident = bool(found_words or all_url_warnings)

        incident_id = (
            f"PH-{uuid.uuid4().hex[:8].upper()}"
            if is_incident
            else "N/A"
        )

        # Security recommendation
        if risk_level == "HIGH":
            recommendation = (
                "High risk based on configured rules. Do not click "
                "links or provide sensitive information. Report the "
                "message to your security team."
            )

        elif risk_level == "MEDIUM":
            recommendation = (
                "Potential risk detected. Verify the sender and "
                "inspect the message before taking action."
            )

        elif is_incident:
            recommendation = (
                "Some indicators were detected. Review the findings "
                "and verify the sender before taking action."
            )

        else:
            recommendation = (
                "No configured phishing indicators were detected. "
                "This does not guarantee that the message is safe."
            )

        # -----------------------------------
        # Display results
        # -----------------------------------
        st.divider()
        st.subheader("📊 Analysis Results")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Final Risk Score",
            f"{risk_score}/100",
        )

        col2.metric(
            "Final Risk Level",
            risk_level,
        )

        col3.metric(
            "Local Score",
            f"{local_risk_score}/100",
        )

        col4.metric(
            "Message Indicators",
            len(found_words),
        )

        st.progress(risk_score / 100)

        if risk_level == "HIGH":
            st.error("🔴 HIGH RISK — Treat this message as potentially dangerous.")
        elif risk_level == "MEDIUM":
            st.warning("🟠 MEDIUM RISK — Review the findings carefully.")
        else:
            st.success(
                "🟢 LOW RISK SCORE — This does not guarantee the message is safe."
            )

        st.write(
            f"**Local message risk points:** {message_points}/60"
        )
        st.write(
            f"**Local URL risk points:** {url_points}/40"
        )

        st.markdown("#### Risk Assessment Reasons")

        for reason in final_risk_reasons:
            st.write(f"- {reason}")

        if is_incident:
            st.subheader("🚨 Incident Details")

            col1, col2 = st.columns(2)
            col1.metric("Incident ID", incident_id)
            col2.metric("Incident Type", incident_type)

            st.write(f"**Analysis time:** {analysis_time}")

        else:
            st.success(
                "No configured phishing indicators detected. "
                "No incident was added to the log."
            )

        # Message indicators
        st.subheader("📝 Phishing Indicators")

        if found_words:
            for word in found_words:
                st.warning(f"Detected: {word}")
        else:
            st.write("No configured phishing indicators detected.")

        # Local URL analysis
        st.subheader("🔗 Local URL Analysis")

        if not urls:
            st.write("No URLs found in the message.")

        for item in url_analysis:
            st.markdown(f"**URL:** `{item['url']}`")

            if item["hostname"]:
                st.write(f"Hostname: `{item['hostname']}`")

            if item["warnings"]:
                for warning in item["warnings"]:
                    st.warning(warning)
            else:
                st.write(
                    "No configured URL warning patterns detected."
                )

        # VirusTotal results
        if use_virustotal:
            st.subheader("🌐 VirusTotal Threat Intelligence")

            if not urls:
                st.write("No URLs were found to look up.")

            elif not VIRUSTOTAL_API_KEY:
                st.warning(
                    "VirusTotal lookup skipped because the API key is missing."
                )

            else:
                st.caption(
                    "VirusTotal results are additional risk signals. "
                    "They do not guarantee that a URL is safe."
                )

                for result in virustotal_results:
                    st.markdown(f"**URL:** `{result['url']}`")
                    status = result.get("status")

                    if status == "found":
                        c1, c2, c3, c4 = st.columns(4)

                        c1.metric("Malicious", result.get("malicious", 0))
                        c2.metric("Suspicious", result.get("suspicious", 0))
                        c3.metric("Harmless", result.get("harmless", 0))
                        c4.metric("Undetected", result.get("undetected", 0))

                        st.write(result.get("message", ""))

                        st.markdown(
                            f"[Open VirusTotal report]({result['report_url']})"
                        )

                    elif status == "not_found":
                        st.info(result["message"])
                        st.markdown(
                            f"[Open VirusTotal URL page]({result['report_url']})"
                        )

                    elif status == "rate_limited":
                        st.warning(result["message"])

                    else:
                        st.warning(
                            result.get(
                                "message",
                                "VirusTotal lookup failed.",
                            )
                        )

        st.subheader("🛡️ Security Recommendation")
        st.write(recommendation)

        st.caption(
            "PhishLens performs local, rule-based analysis. "
            "VirusTotal lookups retrieve existing reports only; "
            "this app does not submit URLs for scanning or open "
            "the URLs themselves. A low score does not guarantee safety."
        )

        # -----------------------------------
        # JSON report
        # -----------------------------------
        report = {
            "incident_id": incident_id,
            "is_incident": is_incident,
            "incident_type": incident_type,
            "tool": "PhishLens",
            "analysis_time": analysis_time,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "local_risk_score": local_risk_score,
            "local_risk_level": local_risk_level,
            "final_risk_reasons": final_risk_reasons,
            "virustotal_malicious_detections": vt_malicious,
            "virustotal_suspicious_detections": vt_suspicious,
            "message_risk_points": message_points,
            "url_risk_points": url_points,
            "security_recommendation": recommendation,
            "suspicious_indicators": found_words,
            "urls_found": urls,
            "url_analysis": url_analysis,
            "virustotal_checked": bool(
                use_virustotal and VIRUSTOTAL_API_KEY
            ),
            "virustotal_results": virustotal_results,
        }

        report_json = json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
        )

        # Save incidents
        if is_incident:
            log_entry = {
                "incident_id": incident_id,
                "incident_type": incident_type,
                "analysis_time": analysis_time,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "local_risk_score": local_risk_score,
                "virustotal_malicious_detections": vt_malicious,
                "virustotal_suspicious_detections": vt_suspicious,
                "suspicious_indicators_count": len(found_words),
                "urls_count": len(urls),
            }

            try:
                with LOG_PATH.open("a", encoding="utf-8") as file:
                    file.write(
                        json.dumps(log_entry, ensure_ascii=False) + "\n"
                    )

                st.success(
                    f"Incident {incident_id} saved to the incident log."
                )

            except OSError as error:
                st.error(f"Could not save incident log: {error}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        st.download_button(
            label="📥 Download JSON Report",
            data=report_json,
            file_name=f"phishlens_report_{timestamp}.json",
            mime="application/json",
        )


# -----------------------------------
# 6. Incident Log and CSV export
# -----------------------------------
st.divider()
st.subheader("📋 Incident Log")

incidents = load_incidents()

if incidents:
    st.write(f"Recorded incidents: {len(incidents)}")

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:
        selected_level = st.selectbox(
            "Filter by risk level",
            ["ALL", "HIGH", "MEDIUM", "LOW"],
        )

    incident_types = sorted({
        incident.get("incident_type", "Unclassified")
        for incident in incidents
    })

    with filter_col2:
        selected_type = st.selectbox(
            "Filter by incident type",
            ["ALL"] + incident_types,
        )

    filtered_incidents = [
        incident
        for incident in incidents
        if (
            selected_level == "ALL"
            or incident.get("risk_level") == selected_level
        )
        and (
            selected_type == "ALL"
            or incident.get("incident_type", "Unclassified")
            == selected_type
        )
    ]

    if filtered_incidents:
        st.dataframe(
            list(reversed(filtered_incidents)),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No incidents match the selected filters.")

    csv_buffer = io.StringIO()

    csv_columns = [
        "incident_id",
        "incident_type",
        "analysis_time",
        "risk_score",
        "risk_level",
        "local_risk_score",
        "virustotal_malicious_detections",
        "virustotal_suspicious_detections",
        "suspicious_indicators_count",
        "urls_count",
    ]

    writer = csv.DictWriter(
        csv_buffer,
        fieldnames=csv_columns,
        extrasaction="ignore",
    )

    writer.writeheader()
    writer.writerows(incidents)

    st.download_button(
        label="📊 Export Incident Log to CSV",
        data="\ufeff" + csv_buffer.getvalue(),
        file_name="phishlens_incident_log.csv",
        mime="text/csv",
    )

else:
    st.info("No incidents recorded yet. Analyze a message to start.")


# -----------------------------------
# 7. SOC Dashboard
# -----------------------------------
st.divider()
st.subheader("📊 SOC Dashboard Statistics")

total_incidents = len(incidents)

high_incidents = sum(
    1 for incident in incidents
    if incident.get("risk_level") == "HIGH"
)

medium_incidents = sum(
    1 for incident in incidents
    if incident.get("risk_level") == "MEDIUM"
)

low_incidents = sum(
    1 for incident in incidents
    if incident.get("risk_level") == "LOW"
)

average_risk = (
    round(
        sum(
            incident.get("risk_score", 0)
            for incident in incidents
        ) / total_incidents,
        1,
    )
    if total_incidents
    else 0
)

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Incidents", total_incidents)
col2.metric("🔴 High Risk", high_incidents)
col3.metric("🟠 Medium Risk", medium_incidents)
col4.metric("🟢 Low Risk", low_incidents)
col5.metric("Average Risk", f"{average_risk}/100")

if total_incidents:
    st.subheader("Incident Risk Distribution")

    st.bar_chart({
        "Incidents": {
            "HIGH": high_incidents,
            "MEDIUM": medium_incidents,
            "LOW": low_incidents,
        }
    })

st.divider()
st.caption(
    "PhishLens | Rule-based phishing screening for security triage. "
    "Use results as indicators, not definitive verdicts."
)
