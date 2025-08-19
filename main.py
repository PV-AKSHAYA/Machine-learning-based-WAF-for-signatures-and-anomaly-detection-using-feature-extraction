from __future__ import annotations
import os
import ipaddress
import logging
import sys
from pathlib import Path
import threading
import time
import signal
import argparse
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_restful import Api, Resource
import pandas as pd
from collections import deque
import math
import json
import random
from sklearn.metrics import precision_recall_curve

import proxy
from core.feature_extractor import FeatureExtractor
from core.hybrid__waf__model import HybridWAFModel
from advanced_waf_logger import AdvancedWAFLogger
from automated_updater import AutomatedModel

# ==== Constants ====
BASE_DIR = Path(__file__).parent
CERT_FILE = BASE_DIR / "cert.pem"
KEY_FILE = BASE_DIR / "key.pem"
MODEL_PATH = BASE_DIR / "hybrid_waf_model.joblib"
CONFIDENCE_THRESHOLD = 0.75
API_PORT = 5001
# (other constants as you have them...)

# Globals
MAX_RECENT_URLS = 50
recent_url_verdicts = deque(maxlen=MAX_RECENT_URLS)


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


def find_optimal_threshold(model, X_val, y_val):
    y_scores = model.predict_proba(X_val)[:, 1]
    precision, recall, thresholds = precision_recall_curve(y_val, y_scores)
    f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
    return thresholds[f1_scores.argmax()]


# Generate synthetic benign samples
def generate_synthetic_benign_samples(count=100):
    benign_samples = []
    common_domains = ["example.com", "mysite.org", "safe.net", "google.com", "amazon.com"]
    common_paths = ["/", "/home", "/about", "/products", "/contact"]

    for _ in range(count):
        method = random.choice(["GET", "POST"])
        domain = random.choice(common_domains)
        path = random.choice(common_paths)
        url = f"https://{domain}{path}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
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
    df_benign = pd.DataFrame(benign_samples)
    return df_benign


# --- WAF Server Class ---
class WAFAPIServer:
    def __init__(self, feature_extractor, ml_model, waf_logger: AdvancedWAFLogger):
        self.app = Flask(__name__)
        self.api = Api(self.app)
        self.fe = feature_extractor
        self.ml = ml_model
        self.waf_logger = waf_logger
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("WAFAPI")

        self._setup_routes()
        self._setup_dashboard_routes()
        self._setup_classify_url_route()

        # ADD THE DEBUG METHOD HERE
    def debug_feature_extraction(self, request_data):
        """Add this method to debug feature extraction"""
        features = self.fe.extract_features(request_data)
        print(f"Extracted features: {features}")
        
        # Check for missing or unexpected features
        expected_features = [
            "url_length", "path_length", "query_length", "param_count",
            "header_count", "payload_length", "sql_keyword_count",
            "xss_signature_count", "command_signature_count", "path_traversal_count",
            "url_entropy", "payload_entropy", "alpha_ratio", "digit_ratio",
            "special_char_ratio", "suspicious_chars_count"
        ]
        
        missing = set(expected_features) - set(features.keys())
        if missing:
            print(f"Missing features: {missing}")
        
        return features    

    def _setup_routes(self):
        class ClassifyRequest(Resource):
            def post(inner):
                try:
                    req = request.get_json(force=True)
                    print("Incoming request JSON:", req)
                    if not req or not all(k in req for k in ("method", "url")):
                        return jsonify({"error": "Missing method or url"}), 400

                    # Input sanitization
                    method = str(req.get("method", "GET")).upper()
                    url = str(req.get("url", "")).strip()
                    payload = req.get("payload", "")
                    payload = "" if payload is None else str(payload)

                    raw_headers = req.get("headers", {})
                    if isinstance(raw_headers, str):
                        try:
                            headers = json.loads(raw_headers)
                            if not isinstance(headers, dict):
                                headers = {}
                        except Exception:
                            headers = {}
                    elif isinstance(raw_headers, dict):
                        headers = raw_headers
                    else:
                        headers = {}
                    headers = {str(k): ("" if v is None else str(v)) for k, v in headers.items()}

                    if not url:
                        return jsonify({"error": "URL is missing"}), 400

                    sanitized_req = {
                        "method": method, "url": url, "payload": payload, "headers": headers
                    }

                    feats = self.debug_feature_extraction(sanitized_req)
                    for k, v in feats.items():
                        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                            feats[k] = 0.0

                    if any([
                        feats.get('has_sqli_signature', 0),
                        feats.get('has_xss_signature', 0),
                        feats.get('has_path_traversal_signature', 0),
                        feats.get('has_cmdinj_signature', 0),
                        feats.get('has_ddos_signature', 0),
                        feats.get('has_brutforce_path', 0),
                        feats.get('has_brutforce_password', 0),
                        feats.get('has_portscan', 0),
                    ]):
                        classification_result = {
                            "is_malicious": True,
                            "confidence": 1.0,
                            "threat_score": 100,
                            "classification": "malicious",
                            "detection_method": "signature-based",
                            "features": feats,
                            "timestamp": datetime.now().isoformat()
                        }
                    else:
                        vec = self._prepare_vec(feats)
                        prob = self.ml.predict_proba([vec])[0][1]
                        pred = prob > CONFIDENCE_THRESHOLD
                        classification_result = {
                            "is_malicious": pred,
                            "confidence": prob,
                            "threat_score": prob * 100,
                            "classification": "malicious" if pred else "benign",
                            "detection_method": "ml-based",
                            "features": feats,
                            "timestamp": datetime.now().isoformat()
                        }

                    self.waf_logger.log_request(sanitized_req, classification_result,
                                                action_taken="blocked" if classification_result["is_malicious"] else "allowed")
                    recent_url_verdicts.append({
                        "url": url,
                        "verdict": classification_result["classification"],
                        "timestamp": classification_result["timestamp"]
                    })
                    return jsonify(classification_result)

                except Exception as ex:
                    self.logger.error(f"Classification error: {ex}")
                    self.logger.error(f"Sanitized request data: {locals().get('sanitized_req', 'N/A')}")
                    self.waf_logger.log_system_event(
                        "classification_failure",
                        {
                            "error": str(ex),
                            "request_data": locals().get('sanitized_req', {})
                        },
                        severity="ERROR"
                    )
                    return jsonify({
                        "success": False,
                        "error": str(ex),
                        "details": "Internal error during classification"
                    }), 500

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

    def run(self, host="0.0.0.0", port=API_PORT, debug=True, use_reloader=False):
        self.waf_logger.log_system_event("api_startup", {"host": host, "port": port}, severity="INFO")
        self.app.run(host=host, port=port, debug=debug, use_reloader=use_reloader)


# === Other Functions ===
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
    
    # Filter to only 0 and 1 classes for 2x2 confusion matrix
    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred)
    mask = np.isin(y_pred_arr, [0, 1])
    y_true_filtered = y_true_arr[mask]
    y_pred_filtered = y_pred_arr[mask]

    accuracy = (y_true_filtered == y_pred_filtered).sum() / len(y_true_filtered) if len(y_true_filtered) > 0 else 0
    print(f"Accuracy (excluding errors): {accuracy:.2%}")
    print(confusion_matrix(y_true_filtered, y_pred_filtered, labels=[0, 1]))
    print(classification_report(y_true_filtered, y_pred_filtered, labels=[0, 1], target_names=["Benign", "Malicious"]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-dataset", help="CSV file for batch testing")
    parser.add_argument("--no-server", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("main_waf_server")
    waf_logger = AdvancedWAFLogger()
    waf_logger.log_system_event("startup", {"message": "Starting server"}, severity="INFO")

    if not MODEL_PATH.exists():
        df = load_multiple_csv(DATA_PATHS)

        # Augment benign data with synthetic samples
        df = pd.concat([df, generate_synthetic_benign_samples(200)], ignore_index=True)

        if df.empty:
            logger.error("No training data available")
            sys.exit(1)

        X, y = prepare_training_data(df)
        model = HybridWAFModel()
        model.train(X, y)   # Now uses SMOTE + CV + threshold tuning
        model.save_model(MODEL_PATH)
    else:
        model = HybridWAFModel.load_model(MODEL_PATH)
        logger.info("Model loaded")

    extractor = FeatureExtractor()
    api = WAFAPIServer(extractor, model, waf_logger)

    if len(proxy.request_log) < 500:
        generate_synthetic_data(600)

    if args.test_dataset:
        threading.Thread(target=lambda: api.run(use_reloader=False), daemon=True).start()
        time.sleep(2)
        print("\n--- Batch Testing ---")
        test_accuracy(args.test_dataset)
        return

    api.run(use_reloader=False)


if __name__ == "__main__":
    if threading.current_thread() == threading.main_thread():
        signal.signal(signal.SIGINT, signal_handler)
    main()
