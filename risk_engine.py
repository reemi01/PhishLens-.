
def calculate_risk(message_indicators, url_warnings):
    """
    Calculate a rule-based phishing risk score.

    Message indicators contribute up to 60 points.
    URL warnings contribute up to 40 points.

    Duplicate indicators and warnings are counted only once.

    Returns a score between 0 and 100 and a risk level.
    """

    # Remove duplicate indicators
    unique_message_indicators = {
        str(item).strip().lower()
        for item in message_indicators
        if str(item).strip()
    }

    unique_url_warnings = {
        str(item).strip().lower()
        for item in url_warnings
        if str(item).strip()
    }

    # Calculate points
    message_points = min(
        len(unique_message_indicators) * 20,
        60
    )

    url_points = min(
        len(unique_url_warnings) * 15,
        40
    )

    risk_score = min(
        message_points + url_points,
        100
    )

    # Determine risk level
    if risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "message_points": message_points,
        "url_points": url_points,
    }
