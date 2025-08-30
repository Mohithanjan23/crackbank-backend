import os
import json
import time
import requests
from typing import Optional
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from hashlib import sha1
import uvicorn

# Load environment variables
load_dotenv()

app = FastAPI()

# --- CORS Configuration ---
origins = [
    "https://crackbank-frontend.vercel.app",
    "http://localhost:5173",  # local dev
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Load breach database ---
def load_breach_data():
    try:
        with open("breaches.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

BREACH_DATABASE = load_breach_data()

# --- Simulated email notification ---
def send_breach_notification(email: str, breaches: list):
    print("\n--- SIMULATED EMAIL NOTIFICATION ---")
    print(f"To: {email}")
    print("From: security@crack-bank.local")
    print("Subject: URGENT: Security Alert - Breach Detected")
    print("-" * 35)
    for breach in breaches:
        print(f"- Source: {breach.get('source','N/A')} | Date: {breach.get('date','N/A')}")
    print("--- END OF SIMULATED EMAIL ---\n")

# --- Routes ---
@app.get("/")
def read_root():
    return {"status": "Crack Bank API is running"}

# --- Hash-based breach check (used by App.jsx) ---
@app.post("/check-breach-hash")
async def check_breach_hash(
    hash: str = Body(..., embed=True),
    last4: Optional[str] = Body(None),
    email: Optional[str] = Body(None)
):
    """
    Checks if SHA1 of provided detail matches any leaked detail in breaches.json.
    """
    user_hash = hash.lower().strip()
    if not user_hash or len(user_hash) != 40:
        raise HTTPException(status_code=400, detail="Invalid SHA-1 hash provided.")

    found_breaches = []
    for breach_name, breach_info in BREACH_DATABASE.items():
        for leaked in breach_info.get("leaked_details", []):
            leaked_hash = sha1(leaked.encode()).hexdigest()
            if leaked_hash == user_hash:
                found_breaches.append({
                    "source": breach_name,
                    "date": breach_info.get("date"),
                    "risk_level": breach_info.get("risk_level"),
                    "description": breach_info.get("description"),
                })

    time.sleep(1.2)  # simulate latency

    if found_breaches:
        if email:
            send_breach_notification(email, found_breaches)
        return {"breached": True, "breaches": found_breaches}
    return {"breached": False}

# --- Summarize with AI (unchanged) ---
@app.post("/summarize-breach")
async def summarize_breach_with_ai(request: dict = Body(...)):
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="Google API key not configured.")
    breach_data = request.get("breach_data")
    if not breach_data:
        raise HTTPException(status_code=400, detail="No breach data provided.")

    breach_details_text = ""
    for i, breach in enumerate(breach_data, 1):
        breach_details_text += (
            f"Breach {i}:\n"
            f"- Source: {breach.get('source','N/A')}\n"
            f"- Date: {breach.get('date','N/A')}\n"
            f"- Risk Level: {breach.get('risk_level','N/A')}\n"
            f"- Description: {breach.get('description','N/A')}\n\n"
        )

    system_prompt = (
        "You are a world-class cybersecurity analyst named 'Cypher'. "
        "Explain to a non-technical user whose banking information was found in a breach. "
        "Keep it serious, clear, and actionable. Use Markdown headings."
    )
    user_prompt = (
        f"My banking detail was found in these breach(es):\n\n{breach_details_text}"
        "Summarize the situation and provide a prioritized list of 3-5 recommended actions."
    )

    api_url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"
    )
    payload = {
        "contents": [{"parts": [{"text": user_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]}
    }

    try:
        resp = requests.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
        resp.raise_for_status()
        result = resp.json()
        candidate = result.get("candidates", [{}])[0]
        content = candidate.get("content", {}).get("parts", [{}])[0].get("text", "")
        if not content:
            raise HTTPException(status_code=500, detail="AI model returned empty response.")
        return {"summary": content}
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=503, detail=f"Error communicating with AI service: {e}")

# --- Entry point for Render ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
