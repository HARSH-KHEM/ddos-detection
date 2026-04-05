"""
DDoS Detection Flask Backend
Trains a Random Forest model on the SDN dataset and exposes prediction endpoints.
"""

import os
import zipfile
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, f1_score, roc_auc_score
from flask import Flask, request, jsonify
from flask_cors import CORS

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

        return jsonify({
            'prediction': prediction,
            'label': 'DDoS' if prediction == 1 else 'Normal',
            'probability_normal': round(float(probabilities[0]), 4),
            'probability_ddos': round(float(probabilities[1]), 4),
            'confidence': round(float(max(probabilities)) * 100, 2),
            'model_used': 'RandomForest',
            'features_used': feature_columns
        })

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


# ─── Startup ──────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    train_model()
    print("\n[*] Starting Flask server on http://0.0.0.0:5050")
    app.run(host='0.0.0.0', port=5050, debug=False)
