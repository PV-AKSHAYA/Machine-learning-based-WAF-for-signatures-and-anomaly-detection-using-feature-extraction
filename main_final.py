from __future__ import annotations
import os
import sys
import math
import json
import logging
import threading
import time
import signal
import argparse
import random
from datetime import datetime
from pathlib import Path
from collections import deque
import ipaddress
import pandas as pd
from flask import Flask, request, jsonify, render_template
from flask_restful import Api, Resource
from sklearn.metrics import (
    precision_recall_curve,
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split

# Local imports (adjust paths as needed)
import proxy
from core.feature_extractor import FeatureExtractor
from core.hybrid__waf__model import HybridWAFModel
from advanced_waf_logger import AdvancedWAFLogger
from automated_updater import AutomatedModel

BASE_DIR = Path(__file__).parent
CERT_FILE = BASE_DIR / "cert.pem"
KEY_FILE = BASE_DIR / "key.pem"
MODEL_PATH = BASE_DIR / "hybrid_waf_model.joblib"
CONFIDENCE_THRESHOLD = 0.75
API_PORT = 5001

DATA_PATHS = [
    BASE_DIR / "waf_training_logs.csv",
    BASE_DIR / "bruteforce.csv",
    BASE_DIR / "dos.csv",
    BASE_DIR / "port_scaning.csv",
    BASE_DIR / "sqli.csv",
    BASE_DIR / "XSS.csv",
    BASE_DIR / "benign2.csv",
    BASE_DIR / "benign3.csv",
    BASE_DIR / "benign4.csv",
    BASE_DIR / "benign5.csv"
]

MAX_RECENT_URLS = 50
recent_url_verdicts = deque(maxlen=MAX_RECENT_URLS)
USE_SIGNATURES = True  # Can be disabled with CLI flag


# ---------------------------
# Utility Functions
# ---------------------------

def signal_handler(signum, frame):
    print("Signal received, exiting...")
    sys.exit(0)


def sanitize_for_json(d):
    for k, v in d.items():
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            d[k] = 0.0
        elif isinstance(v, dict):
            sanitize_for_json(v)
    return d


def sanitize_for_json_request(d):
    if isinstance(d, dict):
        for k, v in d.items():
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                d[k] = 0.0
            elif isinstance(v, (dict, list)):
                sanitize_for_json_request(v)
    elif isinstance(d, list):
        for i, v in enumerate(d):
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                d[i] = 0.0
            elif isinstance(v, (dict, list)):
                sanitize_for_json_request(v)
    return d


def find_optimal_threshold(model, X_val, y_val):
    y_scores = model.predict_proba(X_val)[:, 1]
    precision, recall, thresholds = precision_recall_curve(y_val, y_scores)
    f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
    return thresholds[f1_scores.argmax()]


def read_csv_robust(filepath: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(filepath, on_bad_lines="skip")
    except Exception:
        return pd.read_csv(filepath, error_bad_lines=False)


def load_multiple_csv(files: list[Path]) -> pd.DataFrame:
    dfs = []
    for file in files:
        if file.exists():
            df = read_csv_robust(file)
            dfs.append(df)
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


def prepare_training_data(df: pd.DataFrame):
    df_clean = df.dropna()
    return df_clean.to_dict(orient="records"), df_clean["is_malicious"].values


def generate_synthetic_benign_samples(count=100):
    benign_samples = []
    common_domains = [
        "example.com", "mysite.org", "safe.net", "google.com", "amazon.com",
        "wikipedia.org", "microsoft.com", "apple.com", "python.org", "github.com"
    ]
    common_paths = [
        "/", "/home", "/about", "/products", "/contact", "/blog",
        "/faq", "/support", "/search?q=info", "/profile"
    ]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "curl/7.68.0",
        "Wget/1.20.3 (linux-gnu)"
    ]

    for _ in range(count):
        method = random.choice(["GET", "POST"])
        domain = random.choice(common_domains)
        path = random.choice(common_paths)
        url = f"https://{domain}{path}"
        headers = {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
            "Accept-Language": "en-US,en;q=0.5"
        }
        benign_samples.append({
            "method": method,
            "url": url,
            "payload": "" if method == "GET" else "search=benign+data",
            "headers": json.dumps(headers),
            "is_malicious": 0
        })
    return pd.DataFrame(benign_samples)

def create_balanced_training_data():
    """Create a more balanced dataset for training"""
    # Load existing data
    df = load_multiple_csv(DATA_PATHS)
    
    # Check current balance
    print(f"Original distribution: {df['is_malicious'].value_counts()}")
    
    # Generate more diverse benign samples
    benign_samples = generate_synthetic_benign_samples(count=2000)
    
    # Balance the dataset
    malicious_count = len(df[df['is_malicious'] == 1])
    benign_count = len(df[df['is_malicious'] == 0]) + len(benign_samples)
    
    target_count = max(malicious_count, benign_count)
    
    # Oversample minority class
    if malicious_count < target_count:
        # Add more malicious samples (you'd need to generate these)
        pass
    
    if benign_count < target_count:
        additional_benign = generate_synthetic_benign_samples(target_count - benign_count)
        benign_samples = pd.concat([benign_samples, additional_benign])
    
    final_df = pd.concat([df, benign_samples], ignore_index=True)
    print(f"Balanced distribution: {final_df['is_malicious'].value_counts()}")
    
    return final_df



# ---------------------------
# WAF API Server
# ---------------------------

class WAFAPIServer:
    def __init__(self, feature_extractor, ml_model, waf_logger: AdvancedWAFLogger):
        self.app = Flask(__name__)
        self.api = Api(self.app)
        self.fe = feature_extractor
        self.ml = ml_model
        self.waf_logger = waf_logger
        self.logger = logging.getLogger("WAFAPI")
        self._setup_routes()
        self._setup_dashboard_routes()
        self._setup_classify_url_route()
        logging.basicConfig(level=logging.INFO)
        
    def _setup_routes(self):
        class ClassifyRequest(Resource):
            def post(inner):
                try:
                    req = request.get_json(force=True)
                    if not req or not all(k in req for k in ("method", "url")):
                        return jsonify({"error": "Missing method or url"}), 400
                    print("Incoming request JSON:", req)

                    method = str(req.get("method", "GET")).upper()
                    url = str(req.get("url", "")).strip()
                    payload = "" if req.get("payload") is None else str(req.get("payload"))
                    raw_headers = req.get("headers", {})
                    print(f"Parsed method: {method}, URL: {url}, Payload: {payload}, Headers type: {type(raw_headers)}")

                    if isinstance(raw_headers, str):
                        try:
                            headers = json.loads(raw_headers)
                            if not isinstance(headers, dict):
                                headers = {}
                        except Exception as e:
                            print(f"Error parsing headers JSON string: {e}")
                            headers = {}
                    elif isinstance(raw_headers, dict):
                        headers = raw_headers
                    else:
                        headers = {}

                    headers = {str(k): ("" if v is None else str(v)) for k, v in headers.items()}
                    print("Processed headers:", headers)

                    if not url:
                        return {"error": "URL is missing"}, 400

                    sanitized_req = {
                        "method": method,
                        "url": url,
                        "payload": payload,
                        "headers": headers
                    }
                    print("Sanitized request for feature extraction:", sanitized_req)

                    feats = self.fe.extract_features(sanitized_req)
                    print("Extracted features:", feats)
                    print("Signature flags triggered:",
                          {k: v for k, v in feats.items() if k.startswith("has_") and v == 1})

                    vec = self._prepare_vec(feats)

                    # --- Probability Handling ---
                    prob_array = self.ml.predict_proba([vec])
                    print("prob_array:", prob_array)
                    print("prob_array type:", type(prob_array))
                    try:
                        print("prob_array shape:", prob_array.shape)
                    except Exception as e:
                        print("No shape attribute:", e)

                    import numpy as np
                    try:
                        if hasattr(prob_array, "shape"):
                            if len(prob_array.shape) == 2 and prob_array.shape[1] > 1:
                                prob = float(prob_array[0][-1])
                            elif len(prob_array.shape) == 1:
                                prob = float(prob_array[0])
                            else:
                                return {"error": f"Model output shape odd: {prob_array.shape}"}, 500
                        elif isinstance(prob_array, (float, np.floating)):
                            prob = float(prob_array)
                        elif isinstance(prob_array, list):
                            if len(prob_array) == 1:
                                prob = float(prob_array[0])
                            elif len(prob_array) == 2:
                                prob = float(prob_array[1])
                            else:
                                prob = float(prob_array[-1])
                        else:
                            return {"error": f"Unexpected model output type: {type(prob_array)}"}, 500
                    except Exception as ex:
                        print("Failed to index prob_array:", ex)
                        return {"error": f"Problem extracting probability: {ex}"}, 500
                    # --- End Probability Handling ---

                    print("Probability of malicious:", prob)
                    pred = prob > CONFIDENCE_THRESHOLD

                    classification_result = {
                        "is_malicious": bool(pred),
                        "confidence": float(prob),
                        "threat_score": prob * 100,
                        "classification": "malicious" if pred else "benign",
                        "detection_method": "ml-based",
                        "features": feats,
                        "timestamp": datetime.now().isoformat()
                    }

                    if USE_SIGNATURES and any([
                        feats.get('has_sqli_signature', 0),
                        feats.get('has_xss_signature', 0),
                        feats.get('has_path_traversal_signature', 0),
                        feats.get('has_cmdinj_signature', 0),
                        feats.get('has_ddos_signature', 0),
                        feats.get('has_brutforce_path', 0),
                        feats.get('has_brutforce_password', 0),
                        feats.get('has_portscan_signature', 0),
                    ]):
                        classification_result.update({
                            "is_malicious": True,
                            "confidence": 1.0,
                            "threat_score": 100,
                            "classification": "malicious",
                            "detection_method": "signature-based"
                        })

                    self.waf_logger.log_request(
                        sanitized_req,
                        classification_result,
                        action_taken="blocked" if classification_result["is_malicious"] else "allowed"
                    )

                    proxy.request_log.append({
                        "url": url,
                        "features": feats,
                        "is_malicious": classification_result["is_malicious"],
                        "classification": classification_result["classification"],
                        "timestamp": classification_result["timestamp"]
                    })

                    recent_url_verdicts.append({
                        "url": url,
                        "verdict": classification_result["classification"],
                        "timestamp": classification_result["timestamp"]
                    })

                    return jsonify(classification_result)

                except Exception as ex:
                    self.logger.exception("Classification error")
                    return {"error": str(ex)}, 500

        self.api.add_resource(ClassifyRequest, "/api/classify")


    def _setup_classify_url_route(self):
        @self.app.route("/api/classify_url", methods=["POST"])
        def classify_url():
            try:
                data = request.json
                url = data.get('url')
                if not url:
                    return jsonify(sanitize_for_json({'error': 'No url provided'})), 400
                dummy_req = {"method": "GET", "url": url}
                feats = self.fe.extract_features(dummy_req)
                vec = self._prepare_vec(feats)
                prob = self.ml.predict_proba([vec])[0][1]
                verdict = "malicious" if prob > CONFIDENCE_THRESHOLD else "benign"
                timestamp = datetime.now().isoformat()
                recent_url_verdicts.append({
                    "url": url,
                    "verdict": verdict,
                    "timestamp": timestamp
                })
                result = {'url': url, 'verdict': verdict, 'confidence': prob, 'timestamp': timestamp}
                return jsonify(sanitize_for_json(result))
            except Exception as ex:
                return jsonify(sanitize_for_json({"error": str(ex)})), 500

    def _prepare_vec(self, feats: dict):
        names = [
            "url_length", "path_length", "query_length", "param_count",
            "header_count", "payload_length", "sql_keyword_count",
            "xss_signature_count", "command_signature_count", "path_traversal_count",
            "url_entropy", "payload_entropy", "alpha_ratio", "digit_ratio",
            "special_char_ratio", "suspicious_chars_count"
        ]
        return [feats.get(name, 0) for name in names]

    def _setup_dashboard_routes(self):
        @self.app.route("/")
        def home():
            return render_template("index.html")

        @self.app.route("/api/statistics")
        def api_statistics():
            total_requests = len(proxy.request_log)
            blocked_requests = sum(1 for r in proxy.request_log if r.get("is_malicious"))
            unique_blocked_ips = len(proxy.blocked_ips)
            return jsonify({
                "total_requests": total_requests,
                "blocked_requests": blocked_requests,
                "unique_blocked_ips": unique_blocked_ips
            })
        
        @self.app.route("/api/traffic_chart")
        def api_traffic_chart():
            now = datetime.now().timestamp()
            buckets = [0] * 10
            for rec in proxy.request_log:
                ts = rec.get("ts", now)
                age_minutes = int((now - ts) // 60)
                if 0 <= age_minutes < 10:
                    buckets[9 - age_minutes] += 1
            return jsonify({
                "minutes_ago": list(range(9, -1, -1)),
                "request_counts": buckets
            })

        @self.app.route("/api/attack_types_chart")
        def api_attack_types_chart():
            sql_count = sum(
                1 for r in proxy.request_log
                if r.get("is_malicious") and "sql" in r.get("features", {})
            )
            return jsonify({
                "sql_injection": sql_count,
                "xss": 0,
                "command_injection": 0
            })
        
        

        @self.app.route("/api/threat_severity_chart")
        def api_threat_severity_chart():
            return jsonify({
                "low": 15,
                "medium": 7,
                "high": 3
            })

        @self.app.route("/api/ip_request_chart")
        def api_ip_request_chart():
            ip_counts = {}
            for rec in proxy.request_log:
                ip = rec.get("ip")
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            return jsonify(ip_counts)

        @self.app.route("/api/recent_threats")
        def api_recent_threats():
            threats = [r for r in proxy.request_log if r.get("is_malicious")]
            return jsonify(threats[-10:])

        @self.app.route("/api/blocked_ips")
        def api_blocked_ips():
            return jsonify({
                "blocked_ips": sorted(proxy.blocked_ips),
                "count": len(proxy.blocked_ips)
            })

        @self.app.route("/api/unblock_ip", methods=["POST"])
        def api_unblock_ip():
            ip = request.json.get("ip")
            if ip in proxy.blocked_ips:
                proxy.blocked_ips.remove(ip)
                self.waf_logger.log_system_event("ip_unblocked", {"ip": ip}, severity="INFO")
                return jsonify({"status": "success", "ip": ip})
            return jsonify({"status": "failure", "reason": "IP not found"}), 404
        
        @self.app.route("/api/recent_url_verdicts")
        def api_recent_url_verdicts():
            return jsonify(list(reversed(recent_url_verdicts)))

    def run(self, host="0.0.0.0", port=API_PORT, debug=True):
        print(f"[INFO] Starting WAF API server on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)

def generate_synthetic_data(num_samples=500):
    for _ in range(num_samples):
        ip = f"192.168.0.{random.randint(1,254)}"
        bad = random.random() < 0.1
        proxy.record_request(ip, bad)




def test_accuracy(test_dataset_path):
    import numpy as np
    import requests
    from sklearn.metrics import classification_report, confusion_matrix

    def sanitize(d):
        if isinstance(d, dict):
            return {k: sanitize(v) for k, v in d.items()}
        if isinstance(d, list):
            return [sanitize(x) for x in d]
        if isinstance(d, float):
            if math.isnan(d) or math.isinf(d):
                return 0.0
        return d

    print(f"Testing dataset: {test_dataset_path}")
    df = pd.read_csv(test_dataset_path)
    y_true, y_pred, correct = [], [], 0
    for i, row in df.iterrows():
        try:
            headers = row.get("headers", {})
            if isinstance(headers, str):
                try:
                    headers = eval(headers) if headers != '{}' else {}
                except Exception:
                    headers = {}
            payload = {
                "method": row["method"],
                "url": row["url"],
                "payload": row.get("payload", ""),
                "headers": headers,
            }
            payload = sanitize(payload)
            r = requests.post(f"http://localhost:{API_PORT}/api/classify", json=payload, timeout=10)
            if not r.text.strip():
                raise ValueError("Empty response from server")
            try:
                result = r.json()
                y_true.append(actual)
                y_pred.append(int(result.get("is_malicious", 0)))
                y_proba.append(result.get("confidence", 0.0))
            except Exception:
                print(f"Server returned non-JSON for row {i}: {r.text}")
                raise
            pred = int(result.get("is_malicious", 0))
            actual = int(row["is_malicious"])
            y_true.append(actual)
            y_pred.append(pred)
            if pred == actual:
                correct += 1
        except Exception as e:
            print(f"Row {i} failed: {e}")
            y_true.append(int(row["is_malicious"]))
            y_pred.append(-1)
from sklearn.metrics import balanced_accuracy_score, f1_score, roc_auc_score, precision_score, recall_score
    def evaluate_model_properly(y_true, y_pred, y_proba):
    """Use appropriate metrics for imbalanced datasets"""
         metrics = {
        'balanced_accuracy': balanced_accuracy_score(y_true, y_pred),
        'f1_score': f1_score(y_true, y_pred),
        'roc_auc': roc_auc_score(y_true, y_proba),
        'precision': precision_score(y_true, y_pred),
        'recall': recall_score(y_true, y_pred)
    }
    
    print("Proper evaluation metrics:")
    for metric, value in metrics.items():
        print(f"{metric}: {value:.4f}")
    
    return metrics

    # Filter to only 0 and 1 classes for 2x2 confusion matrix
    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred)
    mask = np.isin(y_pred_arr, [0, 1])
    y_true_filtered = y_true_arr[mask]
    y_pred_filtered = y_pred_arr[mask]
    y_proba_filtered = np.array(y_proba)[mask]

    acc = accuracy_score(y_true_filtered, y_pred_filtered) * 100
    print(f"\nModel Accuracy: {acc:.2f}%")
    print(confusion_matrix(y_true_filtered, y_pred_filtered, labels=[0, 1]))
    evaluate_model_properly(y_true_filtered, y_pred_filtered, y_proba_filtered)
    print(classification_report(y_true_filtered, y_pred_filtered, labels=[0, 1], target_names=["Benign", "Malicious"]))


def main():
    global CONFIDENCE_THRESHOLD, USE_SIGNATURES

    parser = argparse.ArgumentParser()
    parser.add_argument("--test-dataset", help="CSV file for batch testing")
    parser.add_argument("--no-server", action="store_true")
    parser.add_argument("--disable-signatures", action="store_true", help="Disable signature detection")
    args = parser.parse_args()

    if args.disable_signatures:
        USE_SIGNATURES = False
        print("[INFO] Signature-based detection disabled (ML-only mode)")

    logging.basicConfig(level=logging.INFO)
    waf_logger = AdvancedWAFLogger()

    if not MODEL_PATH.exists():
        df = create_balanced_training_data()
        records, y = prepare_training_data(df)
        extractor = FeatureExtractor()
        X = [
            WAFAPIServer(extractor, None, None)._prepare_vec(extractor.extract_features(r))
            for r in records
        ]
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

        model = HybridWAFModel()
        model.train(X_train, y_train)
        try:
            optimal_thresh = find_optimal_threshold(model, X_val, y_val)
            CONFIDENCE_THRESHOLD =  max(0.3, min(optimal_thresh, 0.6))
            print(f"[INFO] Adjusted threshold for imbalanced data: {CONFIDENCE_THRESHOLD:.3f}")
        except Exception as e:
            CONFIDENCE_THRESHOLD = 0.4
            print(f"[WARN] Using conservative threshold: {CONFIDENCE_THRESHOLD}")

        model.save_model(MODEL_PATH)
        MODEL_PATH.with_suffix(".threshold").write_text(str(CONFIDENCE_THRESHOLD))

    else:
        model = HybridWAFModel.load_model(MODEL_PATH)
        extractor = FeatureExtractor()
        threshold_file = MODEL_PATH.with_suffix(".threshold")
        if threshold_file.exists():
            CONFIDENCE_THRESHOLD = float(threshold_file.read_text().strip())
            print(f"[INFO] Loaded saved ML threshold: {CONFIDENCE_THRESHOLD:.3f}")
        else:
            print(f"[WARN] No saved threshold found. Using default {CONFIDENCE_THRESHOLD}")

    api = WAFAPIServer(extractor, model, waf_logger)

    if args.test_dataset:
        threading.Thread(target=lambda: api.run(), daemon=True).start()
        time.sleep(2)
        test_accuracy(args.test_dataset)
        return

    if not args.no_server:
        api.run()

if __name__ == "__main__":
    if threading.current_thread() == threading.main_thread():
        signal.signal(signal.SIGINT, signal_handler)
    main()
