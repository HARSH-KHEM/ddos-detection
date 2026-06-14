# 🛡️ Autonomous DDoS Detection & Response System

> Real-time DDoS detection powered by Machine Learning, Splunk AI, Splunk MCP Server, and autonomous AI-driven incident response.

## 🚀 What It Does

This system autonomously monitors network traffic, detects DDoS attacks in real-time using a trained ML model, streams all events into Splunk for live visualization, queries Splunk data via MCP protocol, and automatically generates AI-powered incident reports — all without any human intervention.

## 🏗️ Architecture

See [architecture_diagram.md](./architecture_diagram.md) for the full visual diagram.
Network Traffic / SDN Dataset

↓

Random Forest ML Model (99.98% accuracy)

↓

Flask Backend API (app.py)

↙        ↓        ↘

Splunk HEC  Groq AI   Splunk MCP Server

(Ingest)   (Reports)  (MCP Protocol)

↓                      ↓

Splunk Dashboard    splunk_run_query

(Live Charts +      (Real-time Data

Native ML Predict)   Access)

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.9+
- Splunk Enterprise (local) with Developer License
- Splunk MCP Server app installed from Splunkbase (App ID: 7931)
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

### 4. Install Splunk MCP Server
- Download from Splunkbase: https://splunkbase.splunk.com/app/7931
- Install: /Applications/Splunk/bin/splunk install app splunk-mcp-server.tgz -auth admin:password
- Restart Splunk
- Go to Splunk MCP Server app → Create MCP Encrypted Token → copy token

### 5. Set environment variables
```bash
export GROQ_API_KEY=your_groq_api_key_here
export SPLUNK_MCP_TOKEN=your_mcp_encrypted_token_here
```

### 6. Run the app
```bash
python3 app.py
```

### 7. Test everything is connected
http://localhost:5050/test

### 8. Run simulation
```bash
curl -X POST http://localhost:5050/simulate
```

### 9. Query Splunk via MCP
```bash
curl -X POST http://localhost:5050/mcp_query \
  -H "Content-Type: application/json" \
  -d '{"query": "index=main sourcetype=ddos_detection | stats count by prediction_label"}'
```

### 10. View live dashboard
http://localhost:8000

## 🔌 API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| /health | GET | Model health and accuracy metrics |
| /predict | POST | Classify traffic as DDoS or Normal |
| /simulate | POST | Replay 200 dataset rows as live traffic |
| /agent | POST | Generate AI incident report for detected attack |
| /mcp_query | POST | Query Splunk data via MCP Server protocol |
| /test | GET | Full diagnostic — tests Splunk HEC, Groq, MCP Token, and ML model |

## 📊 Model Performance

| Model | Accuracy | F1 Score | AUC-ROC |
|---|---|---|---|
| Random Forest | 99.98% | 0.9997 | 1.0 |
| XGBoost | 99.71% | 0.9971 | 0.9998 |
| Decision Tree | 99.60% | 0.9960 | 0.9978 |
| KNN | 98.92% | 0.9891 | 0.9994 |
| Logistic Regression | 87.43% | 0.8731 | 0.9412 |

## 🧱 Tech Stack

- ML Model: Random Forest (scikit-learn), SDN Dataset (104K rows)
- Backend: Python, Flask
- Data Ingestion: Splunk HTTP Event Collector (HEC)
- Visualization: Splunk Enterprise Classic Dashboard
- Native ML: Splunk predict command for traffic forecasting
- MCP Integration: Splunk MCP Server (splunk_run_query tool)
- AI Agent: Groq API — llama-3.3-70b-versatile

## 👨💻 Author

Harsh — B.Tech Software Engineering, Delhi Technological University
GitHub: https://github.com/HARSH-KHEM
Live Demo: https://hackarsh08-ddos-detection.hf.space
