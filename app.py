"""
DDoS Detection Flask Backend
Trains a Random Forest model on the SDN dataset and exposes prediction endpoints.
Includes Splunk HEC integration, traffic simulation, and Groq-powered incident analysis.
"""

import os
import zipfile
import json
import time
import threading
import urllib3
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import requests as http_requests  # aliased to avoid clash with flask.request
from groq import Groq

# Suppress InsecureRequestWarning for local Splunk HEC (SSL disabled)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, f1_score, roc_auc_score
from flask import Flask, request, jsonify
from flask_cors import CORS
import warnings


warnings.filterwarnings('ignore')


app = Flask(__name__)
CORS(app)

# ─── Global Model State ───────────────────────────────────────────────────────
model = None
scaler = None
feature_columns = None
dataset_stats = {}
model_metrics = {}

# Protocol encoding map
PROTOCOL_MAP = {'UDP': 0, 'TCP': 1, 'ICMP': 2}

# ─── Splunk HEC Configuration ──────────────────────────────────────────────────
SPLUNK_HEC_URL = 'http://localhost:8088/services/collector/event'
SPLUNK_HEC_TOKEN = 'b078f947-21ef-4b0d-92f0-8cc4ec61bcaf'
SPLUNK_HEC_HEADERS = {
    'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}',
    'Content-Type': 'application/json'
}

# ─── Groq API Key ──────────────────────────────────────────────────────────────
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')

# ─── Splunk MCP Server Configuration ───────────────────────────────────────────
SPLUNK_MCP_URL = "https://localhost:8089/services/mcp"
SPLUNK_MCP_TOKEN = os.environ.get('SPLUNK_MCP_TOKEN')

# ─── Feature columns expected by the model ─────────────────────────────────────
EXPECTED_FEATURES = [
    'pktcount', 'bytecount', 'pktrate', 'flows',
    'tx_kbps', 'rx_kbps', 'tot_kbps', 'packetins',
    'byteperflow', 'pktperflow', 'Protocol'
]

# Mapping from lowercase input keys to actual dataset column names
INPUT_TO_COL = {
    'pktcount': 'pktcount',
    'bytecount': 'bytecount',
    'pktrate': 'pktrate',
    'flows': 'flows',
    'tx_kbps': 'tx_kbps',
    'rx_kbps': 'rx_kbps',
    'tot_kbps': 'tot_kbps',
    'packetins': 'packetins',
    'byteperflow': 'byteperflow',
    'pktperflow': 'pktperflow',
    'protocol': 'Protocol'
}


# ─── Splunk HEC Helper ─────────────────────────────────────────────────────────

def send_to_splunk_hec(event_data):
    """Send an event to Splunk HEC asynchronously in a background thread."""
    def _send():
        payload = {
            'event': event_data,
            'sourcetype': 'ddos_detection',
            'source': 'flask_app',
            'index': 'main'
        }
        try:
            resp = http_requests.post(
                SPLUNK_HEC_URL,
                headers=SPLUNK_HEC_HEADERS,
                json=payload,
                verify=False,
                timeout=5
            )
            print(f"[Splunk HEC] Status {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"[Splunk HEC] Error sending event: {e}")

    thread = threading.Thread(target=_send, daemon=True)
    thread.start()


def load_dataset():
    """Load the SDN dataset, extracting from zip if needed."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(base_dir, 'dataset_sdn.csv')
    zip_path = os.path.join(base_dir, 'DDOS_Dataset.csv')

    if not os.path.exists(csv_path):
        if os.path.exists(zip_path):
            print("[*] Extracting dataset from zip archive...")
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(base_dir)
        else:
            raise FileNotFoundError(
                "Neither dataset_sdn.csv nor DDOS_Dataset.csv found."
            )

    print("[*] Loading dataset...")
    df = pd.read_csv(csv_path)
    print(f"[✓] Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
    return df


def train_model():
    """Train the Random Forest model on startup."""
    global model, scaler, feature_columns, dataset_stats, model_metrics

    df = load_dataset()

    # ── Compute dataset statistics ──
    dataset_stats = {
        'total_rows': int(df.shape[0]),
        'total_columns': int(df.shape[1]),
        'normal_count': int((df['label'] == 0).sum()),
        'ddos_count': int((df['label'] == 1).sum()),
        'normal_pct': round(float((df['label'] == 0).mean() * 100), 2),
        'ddos_pct': round(float((df['label'] == 1).mean() * 100), 2),
        'feature_stats': {}
    }

    # Encode Protocol column: string -> int
    df['Protocol'] = df['Protocol'].map(PROTOCOL_MAP).fillna(0).astype(int)

    for col in EXPECTED_FEATURES:
        if col in df.columns and pd.api.types.is_numeric_dtype(df[col]):
            dataset_stats['feature_stats'][col] = {
                'mean': round(float(df[col].mean()), 2),
                'std': round(float(df[col].std()), 2),
                'min': round(float(df[col].min()), 2),
                'max': round(float(df[col].max()), 2),
            }

    # ── Prepare features ──
    feature_columns = EXPECTED_FEATURES
    X = df[feature_columns].copy()
    y = df['label'].copy()

    # Handle missing / infinite values
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    # ── Train / test split ──
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── Scale features ──
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # ── Train Random Forest ──
    print("[*] Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)

    # ── Evaluate ──
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)

    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba[:, 1])

    model_metrics = {
        'accuracy': round(float(accuracy), 4),
        'f1_score': round(float(f1), 4),
        'auc_roc': round(float(auc), 4),
        'test_size': int(len(y_test)),
        'train_size': int(len(y_train))
    }

    print(f"[✓] Model trained successfully!")
    print(f"    Accuracy: {accuracy:.4f}")
    print(f"    F1 Score: {f1:.4f}")
    print(f"    AUC-ROC:  {auc:.4f}")


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'model': 'RandomForest',
        'metrics': model_metrics
    })


@app.route('/predict', methods=['POST'])
def predict():
    """Predict whether traffic is Normal (0) or DDoS (1)."""
    if model is None:
        return jsonify({'error': 'Model not loaded yet'}), 503

    data = request.get_json(force=True)

    # Validate required fields
    missing = []
    for key in INPUT_TO_COL.keys():
        if key not in data:
            missing.append(key)

    if missing:
        return jsonify({
            'error': f'Missing required fields: {", ".join(missing)}',
            'required_fields': list(INPUT_TO_COL.keys())
        }), 400

    try:
        # Build feature vector in the correct column order
        feature_values = []
        for col in feature_columns:
            input_key = col.lower() if col.lower() in data else col
            # Find the right key
            for k, v in INPUT_TO_COL.items():
                if v == col:
                    input_key = k
                    break
            feature_values.append(float(data[input_key]))

        features = np.array(feature_values).reshape(1, -1)
        features_scaled = scaler.transform(features)

        prediction = int(model.predict(features_scaled)[0])
        probabilities = model.predict_proba(features_scaled)[0]

        label = 'DDoS' if prediction == 1 else 'Normal'
        confidence = round(float(max(probabilities)) * 100, 2)
        prob_normal = round(float(probabilities[0]), 4)
        prob_ddos = round(float(probabilities[1]), 4)

        result = {
            'prediction': prediction,
            'label': label,
            'probability_normal': prob_normal,
            'probability_ddos': prob_ddos,
            'confidence': confidence,
            'model_used': 'RandomForest',
            'features_used': feature_columns
        }

        # ── Send prediction event to Splunk HEC (async) ──
        splunk_event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'input_features': {k: data.get(k) for k in INPUT_TO_COL.keys()},
            'prediction_label': label,
            'confidence': confidence,
            'probability_ddos': prob_ddos,
            'probability_normal': prob_normal,
            'severity': 'HIGH' if prediction == 1 else 'INFO'
        }
        send_to_splunk_hec(splunk_event)

        return jsonify(result)

    except (ValueError, KeyError, TypeError) as e:
        return jsonify({'error': f'Invalid input data: {str(e)}'}), 400


@app.route('/stats', methods=['GET'])
def stats():
    """Return dataset statistics."""
    return jsonify({
        'dataset': dataset_stats,
        'model': model_metrics,
        'model_name': 'RandomForest',
        'feature_columns': EXPECTED_FEATURES
    })


@app.route('/simulate', methods=['POST'])
def simulate():
    """Read dataset_sdn.csv, pick 200 random rows, and send them to /predict one by one."""
    def _run_simulation():
        base_dir = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(base_dir, 'dataset_sdn.csv')

        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            print(f"[Simulate] Failed to load dataset: {e}")
            return

        # Encode Protocol column to numeric
        df['Protocol'] = df['Protocol'].map(PROTOCOL_MAP).fillna(0).astype(int)

        sample = df.sample(n=min(200, len(df)), random_state=None)
        print(f"[Simulate] Starting simulation with {len(sample)} samples...")

        for idx, (_, row) in enumerate(sample.iterrows()):
            payload = {
                'pktcount': float(row['pktcount']),
                'bytecount': float(row['bytecount']),
                'pktrate': float(row['pktrate']),
                'flows': float(row['flows']),
                'tx_kbps': float(row['tx_kbps']),
                'rx_kbps': float(row['rx_kbps']),
                'tot_kbps': float(row['tot_kbps']),
                'packetins': float(row['packetins']),
                'byteperflow': float(row['byteperflow']),
                'pktperflow': float(row['pktperflow']),
                'protocol': float(row['Protocol'])
            }
            try:
                resp = http_requests.post(
                    'http://localhost:5050/predict',
                    json=payload,
                    timeout=5
                )
                result = resp.json()
                print(f"[Simulate] [{idx+1}/200] {result.get('label', 'N/A')} "
                      f"(confidence: {result.get('confidence', 'N/A')}%)")
            except Exception as e:
                print(f"[Simulate] [{idx+1}/200] Error: {e}")

            time.sleep(0.1)

        print("[Simulate] Simulation complete.")

    thread = threading.Thread(target=_run_simulation, daemon=True)
    thread.start()

    return jsonify({
        'status': 'simulation_started',
        'message': 'Sending 200 random samples to /predict with 0.1s delay between each.',
        'total_samples': 200
    })


@app.route('/agent', methods=['POST'])
def agent():
    """
    Accept attack detection data and use Groq API to generate an incident report.
    Expected payload: {"attack_detected": true, "confidence": 95.2, "features": {...}}
    """
    data = request.get_json(force=True)

    attack_detected = data.get('attack_detected', False)
    confidence = data.get('confidence', 0)
    features = data.get('features', {})

    prompt = f"""You are a cybersecurity incident response analyst. Analyze the following DDoS detection event and generate a structured incident report.

Detection Details:
- Attack Detected: {attack_detected}
- Confidence Score: {confidence}%
- Network Features:
{json.dumps(features, indent=2)}

Please provide a JSON response with the following fields:
- "incident_id": A generated incident ID (format: INC-YYYYMMDD-XXXX)
- "severity": The severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- "attack_type": The likely type of DDoS attack based on the features
- "summary": A brief summary of the incident
- "detailed_analysis": A detailed analysis of the attack patterns observed in the network features
- "recommended_actions": A list of recommended mitigation and response actions
- "estimated_impact": The estimated impact on network operations
- "ioc_indicators": Key indicators of compromise from the features

Respond ONLY with valid JSON, no markdown formatting."""

    try:
        if not GROQ_API_KEY:
            return jsonify({
                'status': 'error',
                'error': 'GROQ_API_KEY environment variable is not set'
            }), 500
        client = Groq(api_key=GROQ_API_KEY)
        chat_completion = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            messages=[{'role': 'user', 'content': prompt}],
            temperature=0.3,
            max_tokens=1024
        )

        response_text = chat_completion.choices[0].message.content

        # Try to parse the Groq response as JSON
        try:
            incident_report = json.loads(response_text)
        except json.JSONDecodeError:
            incident_report = {'raw_response': response_text}

        return jsonify({
            'status': 'success',
            'incident_report': incident_report,
            'input_data': {
                'attack_detected': attack_detected,
                'confidence': confidence,
                'features': features
            }
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': f'Groq API error: {str(e)}'
        }), 502


@app.route('/mcp_query', methods=['POST'])
def mcp_query():
    try:
        data = request.get_json(force=True)
        query = data.get('query')
        
        if not query:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }
        else:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "splunk_run_query",
                    "arguments": {
                        "query": query,
                        "earliest_time": "-24h",
                        "latest_time": "now"
                    }
                }
            }
        
        response = http_requests.post(
            SPLUNK_MCP_URL,
            json=payload,
            headers={
                "Authorization": f"Bearer {SPLUNK_MCP_TOKEN}",
                "Content-Type": "application/json"
            },
            verify=False
        )
        
        mcp_data = response.json()
        ai_analysis = None
        
        if query and GROQ_API_KEY:
            try:
                prompt = (
                    "You are a cybersecurity analyst. Analyze this Splunk query result from a DDoS "
                    "detection system and provide: 1) A brief summary of what the data shows, 2) Any anomalies "
                    "or concerns, 3) Recommended actions. Keep response under 150 words and return ONLY valid JSON "
                    "with keys: summary, anomalies, recommendations. Do not use markdown blocks.\n\n"
                    f"Results:\n{json.dumps(mcp_data)}"
                )
                
                client = Groq(api_key=GROQ_API_KEY)
                chat_completion = client.chat.completions.create(
                    model='llama-3.3-70b-versatile',
                    messages=[{'role': 'user', 'content': prompt}],
                    temperature=0.3,
                    max_tokens=500,
                    response_format={"type": "json_object"}
                )
                
                response_text = chat_completion.choices[0].message.content
                try:
                    ai_analysis = json.loads(response_text)
                except json.JSONDecodeError:
                    ai_analysis = {"raw_response": response_text}
            except Exception as ai_e:
                ai_analysis = {"error": str(ai_e)}
        
        result_payload = {
            "status": "success",
            "mcp_response": mcp_data
        }
        if ai_analysis:
            result_payload["ai_analysis"] = ai_analysis
            
        return jsonify(result_payload)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ─── Diagnostic Endpoint ──────────────────────────────────────────────────────

@app.route('/test', methods=['GET'])
def test_diagnostics():
    """Run a full diagnostic: Splunk HEC, Gemini API, and ML model."""
    report = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'splunk_hec': {'status': 'untested'},
        'groq_api': {'status': 'untested'},
        'ml_model': {'status': 'untested'},
        'splunk_mcp_token_check': 'Splunk MCP Token: Found' if SPLUNK_MCP_TOKEN else 'Splunk MCP Token: Not Found'
    }

    # ── Test 1: Splunk HEC ──
    try:
        test_event = {
            'event': {
                'message': 'Diagnostic test event',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'diagnostic_test'
            },
            'sourcetype': 'ddos_detection',
            'source': 'flask_app_test',
            'index': 'main'
        }
        resp = http_requests.post(
            SPLUNK_HEC_URL,
            headers=SPLUNK_HEC_HEADERS,
            json=test_event,
            verify=False,
            timeout=5
        )
        if resp.status_code == 200:
            report['splunk_hec'] = {
                'status': 'success',
                'status_code': resp.status_code,
                'response': resp.json() if resp.text else {},
                'url': SPLUNK_HEC_URL
            }
        else:
            report['splunk_hec'] = {
                'status': 'failure',
                'status_code': resp.status_code,
                'response': resp.text,
                'url': SPLUNK_HEC_URL
            }
    except Exception as e:
        report['splunk_hec'] = {
            'status': 'failure',
            'error': str(e),
            'url': SPLUNK_HEC_URL
        }

    # ── Test 2: Groq API ──
    try:
        if not GROQ_API_KEY:
            report['groq_api'] = {
                'status': 'failure',
                'error': 'GROQ_API_KEY environment variable is not set'
            }
        else:
            client = Groq(api_key=GROQ_API_KEY)
            chat_completion = client.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=[{'role': 'user', 'content': 'Respond with exactly: OK'}],
                max_tokens=10
            )
            report['groq_api'] = {
                'status': 'success',
                'model': 'llama-3.3-70b-versatile',
                'test_response': chat_completion.choices[0].message.content.strip()
            }
    except Exception as e:
        report['groq_api'] = {
            'status': 'failure',
            'error': str(e)
        }

    # ── Test 3: ML Model ──
    try:
        if model is None:
            report['ml_model'] = {
                'status': 'failure',
                'error': 'Model not loaded'
            }
        else:
            sample_features = np.zeros((1, len(feature_columns)))
            sample_scaled = scaler.transform(sample_features)
            pred = int(model.predict(sample_scaled)[0])
            proba = model.predict_proba(sample_scaled)[0]
            report['ml_model'] = {
                'status': 'success',
                'model': 'RandomForest',
                'test_prediction': 'DDoS' if pred == 1 else 'Normal',
                'test_confidence': round(float(max(proba)) * 100, 2),
                'metrics': model_metrics
            }
    except Exception as e:
        report['ml_model'] = {
            'status': 'failure',
            'error': str(e)
        }

    # Overall status
    all_passed = all(
        report[k]['status'] == 'success'
        for k in ['splunk_hec', 'groq_api', 'ml_model']
    )
    report['overall'] = 'ALL CHECKS PASSED' if all_passed else 'SOME CHECKS FAILED'

    return jsonify(report)


# ─── Startup ──────────────────────────────────────────────────────────────────

def print_startup_status():
    """Print startup diagnostic status for all services."""
    print("\n" + "=" * 60)
    print("  DDoS Detection Service — Startup Diagnostics")
    print("=" * 60)

    # Splunk HEC
    print(f"[✓] Splunk HEC URL: {SPLUNK_HEC_URL}")

    # Groq API Key
    if GROQ_API_KEY:
        masked = GROQ_API_KEY[:8] + '...' + GROQ_API_KEY[-4:]
        print(f"[✓] Groq API Key: Found ({masked})")
    else:
        print("[✗] Groq API Key: Missing (set GROQ_API_KEY env var)")

    # Splunk MCP Token
    if SPLUNK_MCP_TOKEN:
        print("[✓] Splunk MCP Token: Found")
    else:
        print("[✗] Splunk MCP Token: Not Found")

    # Model
    if model is not None:
        print(f"[✓] Model loaded successfully (RandomForest)")
        print(f"    Accuracy: {model_metrics.get('accuracy', 'N/A')}")
        print(f"    F1 Score: {model_metrics.get('f1_score', 'N/A')}")
        print(f"    AUC-ROC:  {model_metrics.get('auc_roc', 'N/A')}")
    else:
        print("[✗] Model: Not loaded")

    print("=" * 60 + "\n")


if __name__ == '__main__':
    train_model()
    print_startup_status()
    print("[*] Starting Flask server on http://0.0.0.0:5050")
    app.run(host='0.0.0.0', port=5050, debug=False)
