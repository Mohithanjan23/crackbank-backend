import os
import json
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
from dotenv import load_dotenv
from typing import Optional

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# --- CORS Configuration ---
# Allows the frontend (running on a different port) to communicate with this backend.
origins = [
    "https://crackbank-frontend.vercel.app",
    "http://localhost:5173", # Default for Vite React apps
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models for Request Bodies ---
class BreachCheckRequest(BaseModel):
    detail: str
    email: Optional[str] = None # Added optional email field for notifications

class AISummaryRequest(BaseModel):
    breach_data: list

# --- Dummy Database Loading ---
def load_breach_data():
    """Loads the dummy breach data from a JSON file."""
    try:
        with open("breaches.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

BREACH_DATABASE = load_breach_data()

# --- Helper Function for Email Notifications ---
def send_breach_notification(email: str, breaches: list):
    """
    Simulates sending an email notification to the user about a data breach.
    In a real application, this would use an email service like SendGrid or AWS SES.
    For this demo, we'll just print to the console where the server is running.
    """
    print("\n--- SIMULATING EMAIL NOTIFICATION ---")
    print(f"To: {email}")
    print("From: security@crack-bank.local")
    print("Subject: URGENT: Security Alert - Your Banking Detail Found in Data Breach")
    print("-" * 35)
    print("We have detected that your banking detail was found in the following data breach(es):\n")
    for breach in breaches:
        print(f"  - Source: {breach.get('source', 'N/A')}")
        print(f"  - Date: {breach.get('date', 'N/A')}")
    print("\nWe strongly recommend you take immediate action to secure your accounts.")
    print("--- END OF SIMULATED EMAIL ---\n")


# --- API Endpoints ---

@app.get("/")
def read_root():
    return {"status": "Crack Bank API is running"}

@app.post("/check-breach")
async def check_breach(request: BreachCheckRequest):
    """
    Checks if a given banking detail is found in the simulated breach database.
    If an email is provided and a breach is found, it triggers a simulated notification.
    """
    user_detail = request.detail
    
    # Basic validation
    if not user_detail or len(user_detail) < 8:
        raise HTTPException(status_code=400, detail="Invalid banking detail provided.")

    found_breaches = []
    
    # Simulate searching in the database
    for breach_name, breach_info in BREACH_DATABASE.items():
        if any(user_detail == item for item in breach_info.get("leaked_details", [])):
            found_breaches.append({
                "source": breach_name,
                "date": breach_info.get("date"),
                "risk_level": breach_info.get("risk_level"),
                "description": breach_info.get("description"),
            })

    # Simulate network latency
    time.sleep(2)

    if found_breaches:
        # If an email was provided in the request, trigger the simulated notification
        if request.email:
            send_breach_notification(request.email, found_breaches)
        return {"breached": True, "breaches": found_breaches}
    else:
        return {"breached": False}

@app.post("/summarize-breach")
async def summarize_breach_with_ai(request: AISummaryRequest):
    """
    Uses the Gemini API to summarize breach details and suggest remediation steps.
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="Google API key not configured.")
    
    if not request.breach_data:
        raise HTTPException(status_code=400, detail="No breach data provided.")

    # Construct a detailed prompt for the AI
    breach_details_text = ""
    for i, breach in enumerate(request.breach_data, 1):
        breach_details_text += (
            f"Breach {i}:\n"
            f"- Source: {breach.get('source', 'N/A')}\n"
            f"- Date: {breach.get('date', 'N/A')}\n"
            f"- Risk Level: {breach.get('risk_level', 'N/A')}\n"
            f"- Description: {breach.get('description', 'N/A')}\n\n"
        )
        
    system_prompt = (
        "You are a world-class cybersecurity analyst. Your name is 'Cypher'. "
        "You are providing a security briefing to a non-technical user whose banking information was found in a data breach. "
        "Your tone should be serious, clear, and reassuring, like a security expert in a hacker movie. "
        "Do not use emojis. Structure your response in Markdown."
    )
    
    user_prompt = (
        f"My banking detail was found in the following data breach(es):\n\n"
        f"{breach_details_text}"
        f"First, provide a brief, one-paragraph summary of the situation and the overall risk. "
        f"Then, provide a clear, actionable, and prioritized list of 3-5 security recommendations under a '## Recommended Actions' heading. "
        f"For example: '1. Contact Your Bank Immediately', '2. Enable Two-Factor Authentication (2FA)'. "
        f"Keep the language direct and easy to understand."
    )
    
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"
    
    payload = {
        "contents": [{"parts": [{"text": user_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]}
    }

    try:
        response = requests.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
        response.raise_for_status()  # Raise an exception for bad status codes
        result = response.json()
        
        candidate = result.get("candidates", [{}])[0]
        content = candidate.get("content", {}).get("parts", [{}])[0].get("text", "")
        
        if not content:
            raise HTTPException(status_code=500, detail="Failed to get a valid response from AI model.")
            
        return {"summary": content}

    except requests.exceptions.RequestException as e:
        print(f"Error calling Gemini API: {e}")
        raise HTTPException(status_code=503, detail=f"Error communicating with the AI service: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="An internal error occurred while processing the AI summary.")

