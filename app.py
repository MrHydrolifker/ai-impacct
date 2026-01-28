from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import re
import requests

app = FastAPI(title="Agentic Scam Honeypot API")

# =========================
# CONFIG
# =========================
SECRET_API_KEY = "YOUR_SECRET_API_KEY"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# =========================
# IN-MEMORY SESSION STORE
# =========================
SESSIONS = {}

# =========================
# DATA MODELS
# =========================
class Message(BaseModel):
    sender: str  # scammer or user
    text: str
    timestamp: datetime


class Metadata(BaseModel):
    channel: Optional[str]
    language: Optional[str]
    locale: Optional[str]


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata]


class HoneypotResponse(BaseModel):
    status: str
    reply: str


# =========================
# UTILS – SCAM DETECTION
# =========================
SCAM_KEYWORDS = [
    "urgent", "verify", "account blocked", "suspended",
    "upi", "bank", "click link", "share otp"
]

def detect_scam(text: str) -> bool:
    text = text.lower()
    return any(keyword in text for keyword in SCAM_KEYWORDS)


# =========================
# UTILS – INTELLIGENCE EXTRACTION
# =========================
def extract_intelligence(text: str, intelligence: dict):
    intelligence["upiIds"].extend(re.findall(r"\b[\w.-]+@upi\b", text))
    intelligence["phoneNumbers"].extend(re.findall(r"\+91\d{10}", text))
    intelligence["phishingLinks"].extend(re.findall(r"https?://\S+", text))
    intelligence["bankAccounts"].extend(re.findall(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}\b", text))

    for kw in SCAM_KEYWORDS:
        if kw in text.lower() and kw not in intelligence["suspiciousKeywords"]:
            intelligence["suspiciousKeywords"].append(kw)


# =========================
# UTILS – AGENT RESPONSE
# =========================
def generate_agent_reply(latest_text: str) -> str:
    # Human-like engagement without revealing detection
    if "upi" in latest_text.lower():
        return "Why do you need my UPI ID for verification?"
    if "blocked" in latest_text.lower():
        return "What caused this issue? I haven’t received any notice."
    return "Can you explain this in more detail?"


# =========================
# FINAL CALLBACK
# =========================
def send_final_callback(session_id: str, session_data: dict):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session_data["totalMessages"],
        "extractedIntelligence": session_data["intelligence"],
        "agentNotes": "Urgency, financial threat, and payment redirection detected"
    }

    try:
        requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5
        )
    except Exception as e:
        print("GUVI Callback Failed:", e)


# =========================
# MAIN API ENDPOINT
# =========================
@app.post("/honeypot/message", response_model=HoneypotResponse)
def honeypot(
    request: HoneypotRequest,
    x_api_key: str = Header(...)
):
    # 🔐 API AUTH
    if x_api_key != SECRET_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = request.sessionId

    # 🆕 Initialize Session
    if session_id not in SESSIONS:
        SESSIONS[session_id] = {
            "messages": [],
            "intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            },
            "scamDetected": False,
            "totalMessages": 0
        }

    session = SESSIONS[session_id]

    # 📩 Store message
    session["messages"].append(request.message)
    session["totalMessages"] += 1

    # 🔍 Scam detection
    if detect_scam(request.message.text):
        session["scamDetected"] = True

    # 🧠 Intelligence extraction
    extract_intelligence(request.message.text, session["intelligence"])

    # 🤖 Agent reply
    reply = generate_agent_reply(request.message.text)

    # 🏁 Final callback condition
    if session["scamDetected"] and session["totalMessages"] >= 15:
        send_final_callback(session_id, session)

    return HoneypotResponse(
        status="success",
        reply=reply
    )
