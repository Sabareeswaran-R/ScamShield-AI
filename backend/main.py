
import re
import joblib

from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from database.database import (
    initialize_database,
    save_analysis,
    get_history,
)


# --------------------------------------------------
# 1. PROJECT CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "models" / "scam_classifier.joblib"

app = FastAPI(
    title="ScamShield AI",
    description=(
        "AI-powered multi-channel scam message "
        "detection and suspicious URL inspection API."
    ),
    version="1.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# 2. REQUEST AND RESPONSE MODELS
# --------------------------------------------------

class AnalyzeRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
    )


class URLAnalysis(BaseModel):
    url: str
    risk_level: str
    indicators: list[str]


class AnalyzeResponse(BaseModel):
    message: str
    prediction: str
    confidence: float
    warning: str
    urls_found: list[URLAnalysis]
    explanations: list[str]
    safety_recommendations: list[str]


# --------------------------------------------------
# 3. LOAD THE TRAINED AI MODEL
# --------------------------------------------------

_model = None


def get_model():
    global _model

    if _model is None:
        if not MODEL_PATH.exists():
            raise RuntimeError(
                f"Trained model not found: {MODEL_PATH}"
            )

        _model = joblib.load(MODEL_PATH)

    return _model


# --------------------------------------------------
# 4. EXTRACT URLS FROM THE MESSAGE
# --------------------------------------------------

def extract_urls(message: str) -> list[str]:
    pattern = r"""https?://[^\s<>\[\]{}"']+"""

    matches = re.findall(pattern, message, flags=re.IGNORECASE)

    cleaned_urls = []

    for url in matches:
        url = url.rstrip(".,!?;:)")
        if url and url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


# --------------------------------------------------
# 5. INSPECT SUSPICIOUS URL INDICATORS
# --------------------------------------------------

def inspect_url(url: str) -> URLAnalysis:
    indicators = []

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if parsed.scheme.lower() != "https":
            indicators.append(
                "URL does not use HTTPS."
            )

        if parsed.username or parsed.password:
            indicators.append(
                "URL contains embedded login credentials."
            )

        if not hostname:
            indicators.append(
                "URL hostname is missing or invalid."
            )

        # Detect literal IPv4 addresses.
        ipv4_pattern = (
            r"^(?:\d{1,3}\.){3}\d{1,3}$"
        )

        if re.match(ipv4_pattern, hostname):
            indicators.append(
                "URL uses an IP address instead of a domain name."
            )

        if "xn--" in hostname.lower():
            indicators.append(
                "Domain contains punycode that needs careful review."
            )

        if len(url) > 200:
            indicators.append(
                "URL is unusually long."
            )

        if len(hostname.split(".")) >= 5:
            indicators.append(
                "Domain has many subdomain levels."
            )

        suspicious_keywords = [
            "login",
            "verify",
            "account",
            "update",
            "secure",
            "bank",
            "password",
            "wallet",
            "free",
            "prize",
            "claim",
            "otp",
        ]

        matching_keywords = [
            keyword
            for keyword in suspicious_keywords
            if keyword in url.lower()
        ]

        if matching_keywords:
            indicators.append(
                "URL contains potentially sensitive keywords: "
                + ", ".join(matching_keywords)
                + "."
            )

        if not hostname or "." not in hostname:
            indicators.append(
                "Domain format needs review."
            )

    except (ValueError, AttributeError):
        indicators.append(
            "URL could not be parsed reliably."
        )

    if any(
        phrase in indicator.lower()
        for indicator in indicators
        for phrase in [
            "credentials",
            "ip address",
            "punycode",
            "missing or invalid",
            "could not be parsed",
        ]
    ):
        risk_level = "High risk"
    elif indicators:
        risk_level = "Needs review"
    else:
        risk_level = "No obvious indicators"

    return URLAnalysis(
        url=url,
        risk_level=risk_level,
        indicators=indicators,
    )


# --------------------------------------------------
# 6. GENERATE MESSAGE EXPLANATIONS
# --------------------------------------------------

def explain_message(message: str) -> list[str]:
    explanations = []
    text = message.lower()

    urgency_words = [
        "urgent",
        "immediately",
        "right now",
        "within minutes",
        "within 15 minutes",
        "act now",
        "expires today",
        "last chance",
    ]

    sensitive_words = [
        "otp",
        "password",
        "pin",
        "cvv",
        "card number",
        "bank details",
        "verification code",
    ]

    threat_words = [
        "blocked",
        "suspended",
        "locked",
        "terminated",
        "legal action",
        "account restricted",
    ]

    financial_lure_words = [
        "reward",
        "prize",
        "lottery",
        "cashback",
        "free money",
        "won money",
        "claim your",
    ]

    payment_words = [
        "processing fee",
        "pay now",
        "send money",
        "transfer money",
        "payment required",
        "refundable fee",
    ]

    verification_words = [
        "verify your account",
        "confirm your account",
        "click here",
        "verify now",
        "update your account",
    ]

    security_words = [
        "unusual activity",
        "unauthorized login",
        "security alert",
        "suspicious login",
    ]

    if any(word in text for word in urgency_words):
        explanations.append(
            "Urgency detected: the message pressures the "
            "recipient to act quickly."
        )

    if any(word in text for word in sensitive_words):
        explanations.append(
            "Sensitive information requested or mentioned: "
            "OTP, password, PIN, or financial details."
        )

    if any(word in text for word in threat_words):
        explanations.append(
            "Threat or account restriction language detected."
        )

    if any(word in text for word in financial_lure_words):
        explanations.append(
            "Possible financial lure: a reward, prize, or "
            "unexpected benefit is mentioned."
        )

    if any(word in text for word in payment_words):
        explanations.append(
            "Payment request detected: the message mentions "
            "a fee, transfer, or payment."
        )

    if any(word in text for word in verification_words):
        explanations.append(
            "Account verification or link-clicking language detected."
        )

    if any(word in text for word in security_words):
        explanations.append(
            "Security-alert language detected; verify the claim "
            "using the official service."
        )

    urls = extract_urls(message)

    if urls:
        explanations.append(
            f"The message contains {len(urls)} URL(s) "
            "that should be checked before opening."
        )

    if not explanations:
        explanations.append(
            "No specific warning phrase was detected by the "
            "rule-based explanation checks. This does not prove "
            "the message is safe."
        )

    return explanations


# --------------------------------------------------
# 7. GENERATE SAFETY RECOMMENDATIONS
# --------------------------------------------------

def get_safety_recommendations(
    prediction: str,
    explanations: list[str],
    urls: list[URLAnalysis],
) -> list[str]:

    recommendations = []

    if prediction.lower() == "scam":
        recommendations.append(
            "Treat this message as suspicious and verify it "
            "before taking any action."
        )

    if any(
        "Sensitive information" in explanation
        for explanation in explanations
    ):
        recommendations.append(
            "Never share OTPs, passwords, PINs, or CVV details "
            "through messages or unverified websites."
        )

    if any(
        "Payment request" in explanation
        for explanation in explanations
    ):
        recommendations.append(
            "Do not pay unexpected fees to receive a prize, "
            "reward, refund, or account benefit."
        )

    if any(
        "Urgency detected" in explanation
        or "Threat or account restriction" in explanation
        for explanation in explanations
    ):
        recommendations.append(
            "Do not panic or act under pressure. Contact the "
            "organisation through its official app or website."
        )

    if urls:
        recommendations.append(
            "Avoid opening suspicious links. Navigate to the "
            "official website yourself instead."
        )

    if any(
        item.risk_level in ["High risk", "Needs review"]
        for item in urls
    ):
        recommendations.append(
            "Review flagged URLs carefully. URL indicators are "
            "heuristics and do not independently prove a site is malicious."
        )

    if not recommendations:
        recommendations.append(
            "Do not share sensitive information unless you have "
            "verified the sender through an independent channel."
        )

    recommendations.append(
        "This tool provides an automated assessment, not a guarantee. "
        "If money or account access is at risk, contact your bank "
        "or service provider through an official channel."
    )

    return recommendations


# --------------------------------------------------
# 8. INITIALIZE THE DATABASE
# --------------------------------------------------

@app.on_event("startup")
def startup_event():
    initialize_database()


# --------------------------------------------------
# 9. ROOT ENDPOINT
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "app": "ScamShield AI",
        "version": "1.3.0",
        "status": "running",
        "endpoints": {
            "analyze": "/api/analyze",
            "history": "/api/history",
            "docs": "/docs",
        },
    }


# --------------------------------------------------
# 10. ANALYZE MESSAGE AND SAVE RESULT
# --------------------------------------------------

@app.post(
    "/api/analyze",
    response_model=AnalyzeResponse,
)
def analyze_message(request: AnalyzeRequest):

    message = request.message.strip()

    if not message:
        raise HTTPException(
            status_code=422,
            detail="Please enter a message to analyze.",
        )

    try:
        model = get_model()

        prediction = str(
            model.predict([message])[0]
        ).lower()

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba([message])[0]
            confidence = float(max(probabilities))
        else:
            confidence = 0.0

        if prediction == "scam":
            warning = (
                "Warning: This message has been classified as "
                "potentially fraudulent. Verify it before acting."
            )
        elif prediction in ["legitimate", "safe", "ham"]:
            warning = (
                "The model did not classify this message as a scam. "
                "This does not guarantee that it is safe."
            )
        else:
            warning = (
                "The model returned a prediction that should be "
                "reviewed carefully."
            )

        urls = extract_urls(message)

        url_results = [
            inspect_url(url)
            for url in urls
        ]

        explanations = explain_message(message)

        recommendations = get_safety_recommendations(
            prediction=prediction,
            explanations=explanations,
            urls=url_results,
        )

        response = AnalyzeResponse(
            message=message,
            prediction=prediction,
            confidence=round(confidence, 4),
            warning=warning,
            urls_found=url_results,
            explanations=explanations,
            safety_recommendations=recommendations,
        )

        # Save each completed analysis in SQLite.
        save_analysis(
            message=message,
            prediction=prediction,
            confidence=round(confidence, 4),
            urls_found=[
                item.dict()
                for item in url_results
            ],
            explanations=explanations,
            safety_recommendations=recommendations,
        )

        return response

    except HTTPException:
        raise

    except Exception as error:
        print(f"Analysis error: {error}")

        raise HTTPException(
            status_code=500,
            detail=(
                "Analysis failed. Check the backend terminal "
                "for details."
            ),
        )


# --------------------------------------------------
# 11. GET PREVIOUS ANALYSIS HISTORY
# --------------------------------------------------

@app.get("/api/history")
def analysis_history():
    try:
        history = get_history(limit=50)

        return {
            "count": len(history),
            "history": history,
        }

    except Exception as error:
        print(f"History error: {error}")

        raise HTTPException(
            status_code=500,
            detail="Could not retrieve analysis history.",
        )
