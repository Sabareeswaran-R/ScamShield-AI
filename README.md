# 🛡️ ScamShield AI
### AI-Powered Multi-Channel Scam Detection Web App

ScamShield AI is a web application designed to analyze suspicious messages and identify potential scam indicators using machine learning and rule-based checks.

## ✨ Features

- **Message Scanner:** Analyze SMS, email, and WhatsApp message text.
- **Machine Learning Prediction:** Classify messages as potentially scam or legitimate.
- **Confidence Score:** Display the model's prediction confidence.
- **AI Explanations:** Highlight potential warning signs in messages.
- **URL Inspection:** Detect URLs and flag basic indicators such as links without HTTPS.
- **Safety Recommendations:** Provide practical online safety guidance.
- **Analysis History:** Store and review previous analyses using SQLite.

## 🧰 Tech Stack

- **Frontend:** React, Vite, CSS
- **Backend:** Python, FastAPI
- **Machine Learning:** scikit-learn, TF-IDF, Logistic Regression
- **Database:** SQLite
- **Model Storage:** Joblib

## 📁 Project Structure

```text
ScamShield-AI/
├── backend/
│   └── main.py
├── data/
│   └── raw/
│       └── scam_messages.csv
├── database/
│   └── database.py
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.js
├── models/
│   ├── scam_classifier.joblib
│   └── train_model.py
└── .gitignore
```

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Sabareeswaran-R/ScamShield-AI.git
cd ScamShield-AI
```

### 2. Set up the Python backend

Create and activate a virtual environment, then install the backend dependencies listed in your project's dependency file.

Start the API from the project root:

```bash
python -m uvicorn backend.main:app --reload
```

API documentation: `http://127.0.0.1:8000/docs`

### 3. Start the frontend

Open a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL displayed by Vite in your terminal.

## ⚠️ Limitations

- The current model was trained on a small sample dataset and needs evaluation on a larger, representative dataset.
- URL inspection uses basic heuristics; it does not establish whether a website is definitively malicious.
- Model confidence is not a guarantee of prediction accuracy.
- This application is an educational prototype and should not replace official security tools or advice.

## 🎯 Project Objective

The goal of ScamShield AI is to demonstrate how machine learning and rule-based indicators can support safer digital communication by helping users recognize potentially suspicious messages.

## 👨‍💻 Author

**Sabareeswaran R**

GitHub: [@Sabareeswaran-R](https://github.com/Sabareeswaran-R)

---

**Disclaimer:** AI predictions are not a guarantee of safety. Verify suspicious messages and links through official channels before taking action.
