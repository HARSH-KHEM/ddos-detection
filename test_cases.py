"""
DDoS Detection API Test Suite
Runs 10 test cases against the Flask backend at localhost:5050
"""

import requests
import json
import sys

API_BASE = "http://localhost:5050"

# ─── Test Cases ─────────────────────────────────────────────────────────────────
TEST_CASES = [
    # --- 3 Clear Normal Traffic Cases ---
    {
        "name": "Normal Traffic #1 - Low activity regular browsing",
        "expected": "Normal",
        "data": {
            "pktcount": 45304, "bytecount": 48294064, "pktrate": 451,
            "flows": 3, "tx_kbps": 0, "rx_kbps": 0, "tot_kbps": 0,
            "packetins": 12, "byteperflow": 1066, "pktperflow": 10, "protocol": 0
        }
    },
    {
        "name": "Normal Traffic #2 - TCP web browsing",
        "expected": "Normal",
        "data": {
            "pktcount": 12050, "bytecount": 8500000, "pktrate": 120,
            "flows": 5, "tx_kbps": 500, "rx_kbps": 1200, "tot_kbps": 1700,
            "packetins": 8, "byteperflow": 2500, "pktperflow": 15, "protocol": 1
        }
    },
    {
        "name": "Normal Traffic #3 - ICMP ping",
        "expected": "Normal",
        "data": {
            "pktcount": 100, "bytecount": 8400, "pktrate": 10,
            "flows": 1, "tx_kbps": 0, "rx_kbps": 0, "tot_kbps": 0,
            "packetins": 2, "byteperflow": 8400, "pktperflow": 100, "protocol": 2
        }
    },

    # --- 3 Clear DDoS Attack Cases ---
    {
        "name": "DDoS Attack #1 - UDP flood",
        "expected": "DDoS",
        "data": {
            "pktcount": 980000, "bytecount": 1200000, "pktrate": 9800,
            "flows": 450, "tx_kbps": 950000, "rx_kbps": 2100, "tot_kbps": 952100,
            "packetins": 8900, "byteperflow": 12, "pktperflow": 2, "protocol": 0
        }
    },
    {
        "name": "DDoS Attack #2 - SYN flood (TCP)",
        "expected": "DDoS",
        "data": {
            "pktcount": 1500000, "bytecount": 90000000, "pktrate": 15000,
            "flows": 800, "tx_kbps": 720000, "rx_kbps": 500, "tot_kbps": 720500,
            "packetins": 12000, "byteperflow": 5, "pktperflow": 1, "protocol": 1
        }
    },
    {
        "name": "DDoS Attack #3 - ICMP flood",
        "expected": "DDoS",
        "data": {
            "pktcount": 750000, "bytecount": 45000000, "pktrate": 7500,
            "flows": 600, "tx_kbps": 400000, "rx_kbps": 1000, "tot_kbps": 401000,
            "packetins": 9500, "byteperflow": 8, "pktperflow": 1, "protocol": 2
        }
    },

    # --- 2 Borderline Cases ---
    {
        "name": "Borderline #1 - Moderate elevated traffic",
        "expected": "either",
        "data": {
            "pktcount": 120000, "bytecount": 15000000, "pktrate": 1200,
            "flows": 20, "tx_kbps": 50000, "rx_kbps": 3000, "tot_kbps": 53000,
            "packetins": 300, "byteperflow": 500, "pktperflow": 8, "protocol": 0
        }
    },
    {
        "name": "Borderline #2 - Slightly suspicious patterns",
        "expected": "either",
        "data": {
            "pktcount": 250000, "bytecount": 30000000, "pktrate": 2500,
            "flows": 40, "tx_kbps": 80000, "rx_kbps": 5000, "tot_kbps": 85000,
            "packetins": 500, "byteperflow": 200, "pktperflow": 5, "protocol": 1
        }
    },

    # --- Edge Case: All Zeros ---
    {
        "name": "Edge Case - All zero values",
        "expected": "Normal",
        "data": {
            "pktcount": 0, "bytecount": 0, "pktrate": 0,
            "flows": 0, "tx_kbps": 0, "rx_kbps": 0, "tot_kbps": 0,
            "packetins": 0, "byteperflow": 0, "pktperflow": 0, "protocol": 0
        }
    },

    # --- Edge Case: Extremely High Values ---
    {
        "name": "Edge Case - Extremely high values",
        "expected": "DDoS",
        "data": {
            "pktcount": 99999999, "bytecount": 999999999, "pktrate": 999999,
            "flows": 99999, "tx_kbps": 9999999, "rx_kbps": 9999999, "tot_kbps": 9999999,
            "packetins": 999999, "byteperflow": 1, "pktperflow": 1, "protocol": 0
        }
    },
]


def run_tests():
    print("=" * 70)
    print("  DDoS Detection API — Test Suite")
    print("=" * 70)

    # 1. Health check
    print("\n[1/3] Checking backend health...")
    try:
        r = requests.get(f"{API_BASE}/health", timeout=5)
        health = r.json()
        print(f"  ✅ Backend healthy | Model: {health.get('model')} | Loaded: {health.get('model_loaded')}")
        metrics = health.get('metrics', {})
        print(f"     Accuracy: {metrics.get('accuracy')} | F1: {metrics.get('f1_score')} | AUC: {metrics.get('auc_roc')}")
    except Exception as e:
        print(f"  ❌ Backend unreachable: {e}")
        print("  ⚠ Start the Flask server first: python3 app.py")
        sys.exit(1)

    # 2. Stats endpoint
    print("\n[2/3] Checking /stats endpoint...")
    try:
        r = requests.get(f"{API_BASE}/stats", timeout=5)
        stats = r.json()
        ds = stats.get('dataset', {})
        print(f"  ✅ Dataset: {ds.get('total_rows')} rows | Normal: {ds.get('normal_count')} | DDoS: {ds.get('ddos_count')}")
    except Exception as e:
        print(f"  ❌ Stats endpoint failed: {e}")

    # 3. Prediction tests
    print(f"\n[3/3] Running {len(TEST_CASES)} prediction tests...\n")
    print("-" * 70)

    passed = 0
    failed = 0
    results = []

    for i, tc in enumerate(TEST_CASES, 1):
        name = tc["name"]
        expected = tc["expected"]
        try:
            r = requests.post(f"{API_BASE}/predict", json=tc["data"], timeout=10)
            if r.status_code != 200:
                status = "FAIL"
                detail = f"HTTP {r.status_code}: {r.text[:100]}"
                failed += 1
            else:
                result = r.json()
                label = result.get("label", "?")
                prob_n = result.get("probability_normal", 0)
                prob_d = result.get("probability_ddos", 0)
                confidence = result.get("confidence", 0)

                if expected == "either":
                    status = "PASS"
                    passed += 1
                elif label == expected:
                    status = "PASS"
                    passed += 1
                else:
                    status = "FAIL"
                    failed += 1

                detail = f"Predicted: {label} | P(Normal)={prob_n:.4f} P(DDoS)={prob_d:.4f} | Conf: {confidence}%"

        except Exception as e:
            status = "FAIL"
            detail = f"Error: {str(e)}"
            failed += 1

        icon = "✅" if status == "PASS" else "❌"
        print(f"  {icon} Test {i:2d}: {name}")
        print(f"         Expected: {expected} | {detail}")
        print()

    # Summary
    print("=" * 70)
    total = passed + failed
    print(f"  RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    if failed == 0:
        print("  🎉 All tests passed!")
    else:
        print(f"  ⚠ {failed} test(s) failed — review above for details")
    print("=" * 70)

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
