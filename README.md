# 🛡️ Autonomous DDoS Detection & Response System

> Real-time DDoS detection powered by Machine Learning, Splunk, and AI-driven autonomous incident response.

## 🚀 What It Does

This system autonomously monitors network traffic, detects DDoS attacks in real-time using a trained ML model, streams all events into Splunk for live visualization, and automatically generates AI-powered incident reports — all without any human intervention.

## Pipeline
Simulated Network Traffic
↓
Random Forest ML Model (99.98% accuracy)
↓
Flask Backend API (app.py)
↓
Splunk HEC — real-time data ingestion
↓
Splunk Dashboard — live visualization
↓
Groq AI Agent — autonomous incident report generation

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.9+
- Splunk Enterprise (local) with Developer License
- Groq API key (free at https://console.groq.com)

### 1. Clone the repo
```bash
git clone https://github.com/HARSH-KHEM/ddos-detection
cd ddos-detection
```

### 2. Install dependencies
```bash
pip install flask flask-cors scikit-learn pandas numpy requests groq
```

### 3. Configure Splunk HEC
- Go to Splunk → Settings → Data Inputs → HTTP Event Collector
- Global Settings → disable SSL → Save
- Create new token named ddos-detection → copy the token
- Update the token in app.py (SPLUNK_TOKEN variable)

### 4. Set environment variables
```bash
export GROQ_API_KEY=your_groq_api_key_here
```

### 5. Run the app
```bash
python3 app.py
```

### 6. Test everything is connected
http://localhost:5050/test

### 7. Run simulation
```bash
curl -X POST http://localhost:5050/simulate
```

### 8. View live dashboard
http://localhost:8000

## 🔌 API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| /health | GET | Model health and accuracy metrics |
| /predict | POST | Classify traffic as DDoS or Normal |
| /simulate | POST | Replay 200 dataset rows as live traffic |
| /agent | POST | Generate AI incident report for detected attack |
| /test | GET | Full diagnostic — tests Splunk, Groq, and ML model |

## 📊 Model Performance

| Model | Accuracy | F1 Score | AUC-ROC |
|---|---|---|---|
| Random Forest | 99.98% | 0.9997 | 1.0 |
| XGBoost | 99.71% | 0.9971 | 0.9998 |
| Decision Tree | 99.60% | 0.9960 | 0.9978 |
| KNN | 98.92% | 0.9891 | 0.9994 |
| Logistic Regression | 87.43% | 0.8731 | 0.9412 |

## 🧱 Tech Stack

- ML Model: Random Forest (scikit-learn), SDN Dataset
- Backend: Python, Flask
- Data Ingestion: Splunk HTTP Event Collector
- Visualization: Splunk Enterprise Classic Dashboard
- AI Agent: Groq API — llama-3.3-70b-versatile

## 👨💻 Author

Harsh — B.Tech Software Engineering, Delhi Technological University
GitHub: https://github.com/HARSH-KHEM
