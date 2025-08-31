🏦 Crack Bank - Cybernetic Breach Analysis Protocol
Crack Bank is a full-stack web and mobile application designed to simulate the process of checking for data breaches related to financial details. It features a "hacker terminal" aesthetic and leverages Google's Gemini AI to provide users with a security briefing and actionable advice if a breach is detected in its simulated database.

🌟 Key Features
Simulated Breach Check: Users can enter a banking detail (card number, IBAN, etc.) to check against a mock database of known data leaks.

AI-Powered Security Briefing: If a breach is found, the application uses the Gemini API to generate a clear, actionable security summary and remediation steps.

Optional Email Alerts: Users can provide an email address to receive a simulated security notification.

Cross-Platform: Available as both a responsive web application and a native mobile app for iOS and Android.

Immersive UI: A "hacker terminal" theme with typing effects and a matrix-style background to create an engaging user experience.

📸 Screenshots
Web Application
**

Mobile Application (iOS/Android)
**

🛠️ Tech Stack & Architecture
The project is a full-stack application composed of a Python backend, a React web frontend, and a React Native mobile application.

Component

Technology

Description

Backend

<img src="https://www.google.com/search?q=https://img.shields.io/badge/FastAPI-0C9D88%3Flogo%3Dfastapi" alt="FastAPI"/>

Serves the core API for checking breach data and interacting with Gemini.

Web Frontend

<img src="https://www.google.com/search?q=https://img.shields.io/badge/React-20232A%3Flogo%3Dreact%26logoColor%3D61DAFB" alt="React"/> & <img src="https://www.google.com/search?q=https://img.shields.io/badge/Tailwind_CSS-38B2AC%3Flogo%3Dtailwind-css" alt="Tailwind CSS"/>

Provides a responsive and interactive user interface for web browsers.

Mobile App

<img src="https://www.google.com/search?q=https://img.shields.io/badge/React_Native-20232A%3Flogo%3Dreact%26logoColor%3D61DAFB" alt="React Native"/> & <img src="https://www.google.com/search?q=https://img.shields.io/badge/Expo-000020%3Flogo%3Dexpo%26logoColor%3Dwhite" alt="Expo"/>

Delivers a native mobile experience for both iOS and Android platforms.

AI Model

<img src="https://www.google.com/search?q=https://img.shields.io/badge/Google_Gemini-8E77D5%3Flogo%3Dgoogle-gemini" alt="Gemini"/>

Powers the AI-driven security summary and recommendations.

System Architecture
**

🚀 Getting Started
Follow these instructions to set up and run the project locally for development.

Prerequisites
Python 3.9+

Node.js and npm (or yarn)

A Google API Key with the "Generative Language API" enabled.

Expo Go app on your mobile device (for running the mobile app).

1. Backend Setup (FastAPI)
# Clone the repository
git clone [https://github.com/Mohithanjan23/crackbank-backend.git](https://github.com/Mohithanjan23/crackbank-backend.git)
cd crackbank-backend

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the required packages
pip install -r requirements.txt

# Create a .env file in the root directory
# and add your Google API key
echo 'GOOGLE_API_KEY="YOUR_GOOGLE_API_KEY"' > .env

# Run the backend server
uvicorn main:app --reload

The backend API will now be running at http://127.0.0.1:8000.

2. Web Frontend Setup (React)
# Navigate to your frontend project directory
# (Assuming you have it from the initial setup)
cd path/to/your/frontend

# Install dependencies
npm install

# Start the development server
npm run dev

The React web application will be accessible at http://localhost:5173.

3. Mobile App Setup (React Native with Expo)
# (From the mobile app guide)
# Initialize a new Expo project
npx create-expo-app crackbank-mobile
cd crackbank-mobile

# Replace the default App.js and package.json with the
# mobile-specific versions provided.

# Install dependencies
npm install

# IMPORTANT: Open App.js and update the API_BASE_URL
# to point to your local machine's IP address
# e.g., '[http://192.168.1.10:8000/api](http://192.168.1.10:8000/api)'

# Start the development server
npx expo start

Scan the QR code with the Expo Go app on your phone to run the mobile application.

🚨 Security Disclaimer
Do NOT use your real financial information in this application. All data breach checks are simulated and performed against a dummy breaches.json file.

Protect Your API Key. The .env file containing your GOOGLE_API_KEY should never be committed to version control. Ensure it is added to your .gitignore file.

📄 License
This project is licensed under the MIT License. See the LICENSE file for details.
