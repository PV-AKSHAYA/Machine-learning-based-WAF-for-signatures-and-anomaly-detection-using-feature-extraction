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
from typing import List, Dict, Any

import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, render_template
from flask_restful import Api, Resource
from sklearn.metrics import (
    precision_recall_curve,
    accuracy_score,
    classification_report,
    confusion_matrix,
    balanced_accuracy_score,
    f1_score,
    roc_auc_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

# Local imports (adjust paths as needed)
import proxy
from core.feature_extractor import FeatureExtractor
from core.hybrid__waf__model import HybridWAFModel
from advanced_waf_logger import AdvancedWAFLogger
from automated_updater import AutomatedModel


# ---------------------------
# Configuration / Globals
# ---------------------------
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
    BASE_DIR / "benign5.csv",
]

MAX_RECENT_URLS = 50
recent_url_verdicts = deque(maxlen=MAX_RECENT_URLS)
USE_SIGNATURES = True  # CLI flag can disable


# ---------------------------
# Utility Functions
# ---------------------------
def signal_handler(signum, frame):
    print("Signal received, exiting...")
    sys.exit(0)


def sanitize_for_json(obj: Any) -> Any:
    """
    Recursively replace NaN/Inf floats with 0.0 so jsonify doesn't fail.
    """
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_for_json(v) for v in obj]
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return 0.0
    return obj


def find_optimal_threshold(model, X_val, y_val, min_thresh=0.3, max_thresh=0.6):
    """
    Find threshold that maximizes F1 on validation set, clamp within [min_thresh,max_thresh].
    """
    try:
        y_scores = np.asarray(model.predict_proba(X_val))[:, 1]
        precision, recall, thresholds = precision_recall_curve(y_val, y_scores)
        if thresholds.size == 0:
            return 0.4
        f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
        best = thresholds[f1_scores.argmax()]
        return max(min_thresh, min(best, max_thresh))
    except Exception:
        return 0.4


def read_csv_robust(filepath: Path) -> pd.DataFrame:
    """
    Read CSV robustly, skipping bad lines when possible.
    """
    try:
        return pd.read_csv(filepath, on_bad_lines="skip")
    except TypeError:
        # older pandas versions
        return pd.read_csv(filepath, error_bad_lines=False)
    except Exception:
        return pd.DataFrame()


def load_multiple_csv(files: List[Path]) -> pd.DataFrame:
    dfs = []
    for file in files:
        if file.exists():
            df = read_csv_robust(file)
            if not df.empty:
                dfs.append(df)
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


def prepare_training_data(df: pd.DataFrame):
    if df.empty:
        return [], np.array([])
    if "is_malicious" not in df.columns:
        raise ValueError("Training data must contain 'is_malicious' column")
    df_clean = df.dropna(subset=["is_malicious"])  # keep other NaNs handled later
    return df_clean.to_dict(orient="records"), df_clean["is_malicious"].astype(int).values


def generate_synthetic_benign_samples(count=100) -> pd.DataFrame:
    benign_samples = []
    common_domains = [
        "example.com", "mysite.org", "safe.net", "google.com", "amazon.com",
        "wikipedia.org", "microsoft.com", "apple.com", "python.org", "github.com",
    ]
    common_paths = [
        "/", "/home", "/about", "/products", "/contact", "/blog",
        "/faq", "/support", "/search?q=info", "/profile",
    ]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "curl/7.68.0",
        "Wget/1.20.3 (linux-gnu)",
    ]

    for _ in range(count):
        method = random.choice(["GET", "POST"])
        domain = random.choice(['example.uk','myapp.biz','secure.info','shoponline.co'])
        path = random.choice(['example.uk','myapp.biz','secure.info','shoponline.co'])
        url = f"https://{domain}{path}"
        headers = {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": random.choice(["http://google.com", "http://bing.com"]),
            "Cookie": f"sessionid={random.randint(1000,9999)}; userid={random.randint(1,1000)}"
        }
        benign_samples.append({
            "method": method,
            "url": url,
            "payload": "" if method == "GET" else "data=normaldata",
            "headers": json.dumps(headers),
            "is_malicious": 0,
        })
    return pd.DataFrame(benign_samples)


def create_balanced_training_data() -> pd.DataFrame:
    df = load_multiple_csv(DATA_PATHS)
    if df.empty or "is_malicious" not in df.columns:
        # nothing to load — return synthetic benign dataset so training code can continue
        print("[WARN] No training CSVs found or missing 'is_malicious' column. Creating synthetic dataset.")
        return generate_synthetic_benign_samples(count=2000)

    # Ensure 'is_malicious' is int
    df["is_malicious"] = df["is_malicious"].fillna(0).astype(int)
    print("Original distribution:")
    print(df["is_malicious"].value_counts())

    benign_samples = generate_synthetic_benign_samples(count=2000)
    malicious_count = int((df["is_malicious"] == 1).sum())
    benign_count = int((df["is_malicious"] == 0).sum()) + len(benign_samples)
    target_count = max(1, malicious_count, benign_count)

    # Oversample malicious if required — user might plug custom generator here
    if malicious_count < target_count:
        # If you have no generator for malicious samples, we just duplicate existing malicious rows
        malicious_df = df[df["is_malicious"] == 1]
        if not malicious_df.empty:
            to_add = malicious_df.sample(target_count - malicious_count, replace=True)
            df = pd.concat([df, to_add], ignore_index=True)

    # Add benign samples if needed
    if benign_count < target_count:
        additional_benign = generate_synthetic_benign_samples(target_count - benign_count)
        benign_samples = pd.concat([benign_samples, additional_benign], ignore_index=True)

    final_df = pd.concat([df, benign_samples], ignore_index=True)
    print("Balanced distribution:")
    print(final_df["is_malicious"].value_counts())
    return final_df


# ---------------------------
# WAF API Server
# ---------------------------
class WAFAPIServer:
    def __init__(self, feature_extractor: FeatureExtractor, ml_model: HybridWAFModel, waf_logger: AdvancedWAFLogger):
        self.app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
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
        server = self

        class ClassifyRequest(Resource):
            def post(inner):
                try:
                    req = request.get_json(force=True)
                    if not req or not all(k in req for k in ("method", "url")):
                        return jsonify({"error": "Missing method or url"}), 400

                    method = str(req.get("method", "GET")).upper()
                    url = str(req.get("url", "")).strip()
                    payload = "" if req.get("payload") is None else str(req.get("payload"))
                    raw_headers = req.get("headers", {})

                    # normalize headers
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
                        return {"error": "URL is missing"}, 400

                    sanitized_req = {
                        "method": method,
                        "url": url,
                        "payload": payload,
                        "headers": headers
                    }

                    feats = server.fe.extract_features(sanitized_req)
                    vec = server._prepare_vec(feats)

                    # --- Probability Handling (robust) ---
                    prob = 0.0
                    try:
                        prob_array = server.ml.predict_proba([vec])
                        # many sklearn-like models return shape (n_samples, n_classes)
                        if hasattr(prob_array, "shape"):
                            if len(prob_array.shape) == 2 and prob_array.shape[1] > 1:
                                prob = float(prob_array[0][-1])
                            elif len(prob_array.shape) == 1:
                                prob = float(prob_array[0])
                            else:
                                # fallback
                                prob = float(np.ravel(prob_array)[-1])
                        elif isinstance(prob_array, (float, np.floating)):
                            prob = float(prob_array)
                        elif isinstance(prob_array, (list, tuple, np.ndarray)):
                            flat = np.ravel(prob_array)
                            prob = float(flat[-1]) if flat.size > 0 else 0.0
                        else:
                            return {"error": f"Unexpected model output type: {type(prob_array)}"}, 500
                    except Exception as ex:
                        server.logger.exception("Failed to compute probability")
                        return {"error": f"Problem extracting probability: {ex}"}, 500

                    pred = prob > CONFIDENCE_THRESHOLD

                    classification_result = {
                        "is_malicious": bool(pred),
                        "confidence": float(prob),
                        "threat_score": float(prob * 100),
                        "classification": "malicious" if pred else "benign",
                        "detection_method": "ml-based",
                        "features": feats,
                        "timestamp": datetime.now().isoformat(),
                    }

                    # signature overrides
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
                            "threat_score": 100.0,
                            "classification": "malicious",
                            "detection_method": "signature-based",
                        })
                    
                    # Debug check for possibly misclassified benign .uk domains
                    if classification_result["is_malicious"] and sanitized_req["url"].endswith(".uk"):
                       print("[DEBUG] Possibly misclassified benign:", sanitized_req, feats)

                    # logging + proxy bookkeeping
                    try:
                        server.waf_logger.log_request(
                            sanitized_req,
                            classification_result,
                            action_taken="blocked" if classification_result["is_malicious"] else "allowed"
                        )
                    except Exception:
                        server.logger.exception("WAF logger failed")

                    # maintain a lightweight proxy log if module supports it
                    try:
                        proxy.request_log.append({
                            "url": url,
                            "features": feats,
                            "is_malicious": classification_result["is_malicious"],
                            "classification": classification_result["classification"],
                            "timestamp": classification_result["timestamp"],
                            "ts": datetime.now().timestamp()
                        })
                    except Exception:
                        # ensure proxy has necessary structures
                        try:
                            proxy.request_log = getattr(proxy, "request_log", [])
                            proxy.request_log.append({
                                "url": url,
                                "features": feats,
                                "is_malicious": classification_result["is_malicious"],
                                "classification": classification_result["classification"],
                                "timestamp": classification_result["timestamp"],
                                "ts": datetime.now().timestamp()
                            })
                        except Exception:
                            server.logger.exception("Failed to append to proxy.request_log")

                    # recent verdicts
                    recent_url_verdicts.append({
                        "url": url,
                        "verdict": classification_result["classification"],
                        "timestamp": classification_result["timestamp"]
                    })

                    return jsonify(sanitize_for_json(classification_result))

                except Exception as ex:
                    server.logger.exception("Classification error")
                    return {"error": str(ex)}, 500

        self.api.add_resource(ClassifyRequest, "/api/classify")

    def _setup_classify_url_route(self):
        @self.app.route("/api/classify_url", methods=["POST"])
        def classify_url():
            try:
                data = request.json or {}
                url = data.get("url")
                if not url:
                    return jsonify(sanitize_for_json({"error": "No url provided"})), 400

                dummy_req = {"method": "GET", "url": url, "payload": "", "headers": {}}
                feats = self.fe.extract_features(dummy_req)
                vec = self._prepare_vec(feats)

                # robust prob extraction
                prob = 0.0
                try:
                    prob_array = self.ml.predict_proba([vec])
                    prob = float(np.ravel(prob_array)[-1]) if np.size(prob_array) else 0.0
                except Exception as e:
                    self.logger.exception("Failed to get probability for classify_url")
                    return jsonify(sanitize_for_json({"error": str(e)})), 500

                verdict = "malicious" if prob > CONFIDENCE_THRESHOLD else "benign"
                timestamp = datetime.now().isoformat()
                recent_url_verdicts.append({"url": url, "verdict": verdict, "timestamp": timestamp})
                result = {"url": url, "verdict": verdict, "confidence": float(prob), "timestamp": timestamp}
                return jsonify(sanitize_for_json(result))
            except Exception as ex:
                self.logger.exception("classify_url error")
                return jsonify(sanitize_for_json({"error": str(ex)})), 500

    def _prepare_vec(self, feats: Dict[str, Any]):
        """
        Keep feature ordering stable between training and inference.
        Extend this list if you add more features in FeatureExtractor.
        """
        names = [
            "url_length", "path_length", "query_length", "param_count",
            "header_count", "payload_length", "sql_keyword_count",
            "xss_signature_count", "command_signature_count", "path_traversal_count",
            "url_entropy", "payload_entropy", "alpha_ratio", "digit_ratio",
            "special_char_ratio", "suspicious_chars_count"
        ]
        return [float(feats.get(name, 0.0)) for name in names]

    def _setup_dashboard_routes(self):
        @self.app.route("/")
        def home():
            # if you have an index.html in templates, it will render. Otherwise return simple JSON.
            try:
                return render_template("index.html")
            except Exception:
                return jsonify({"status": "WAF API running", "time": datetime.now().isoformat()})

        @self.app.route("/api/statistics")
        def api_statistics():
            total_requests = len(getattr(proxy, "request_log", []))
            blocked_requests = sum(1 for r in getattr(proxy, "request_log", []) if r.get("is_malicious"))
            unique_blocked_ips = len(getattr(proxy, "blocked_ips", []))
            return jsonify({
                "total_requests": total_requests,
                "blocked_requests": blocked_requests,
                "unique_blocked_ips": unique_blocked_ips
            })

        @self.app.route("/api/traffic_chart")
        def api_traffic_chart():
            now_ts = datetime.now().timestamp()
            buckets = [0] * 10
            for rec in getattr(proxy, "request_log", []):
                ts = rec.get("ts", now_ts)
                age_minutes = int((now_ts - ts) // 60)
                if 0 <= age_minutes < 10:
                    buckets[9 - age_minutes] += 1
            return jsonify({"minutes_ago": list(range(9, -1, -1)), "request_counts": buckets})

        @self.app.route("/api/attack_types_chart")
        def api_attack_types_chart():
            sql_count = sum(
                1 for r in getattr(proxy, "request_log", [])
                if r.get("is_malicious") and isinstance(r.get("features"), dict) and r["features"].get("sql_keyword_count", 0) > 0
            )
            xss_count = sum(
                1 for r in getattr(proxy, "request_log", [])
                if r.get("is_malicious") and isinstance(r.get("features"), dict) and r["features"].get("xss_signature_count", 0) > 0
            )
            return jsonify({"sql_injection": sql_count, "xss": xss_count, "command_injection": 0})

        @self.app.route("/api/threat_severity_chart")
        def api_threat_severity_chart():
            # placeholder static values — replace with real aggregation if you compute severities
            return jsonify({"low": 15, "medium": 7, "high": 3})

        @self.app.route("/api/ip_request_chart")
        def api_ip_request_chart():
            ip_counts = {}
            for rec in getattr(proxy, "request_log", []):
                ip = rec.get("ip")
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            return jsonify(ip_counts)

        @self.app.route("/api/recent_threats")
        def api_recent_threats():
            threats = [r for r in getattr(proxy, "request_log", []) if r.get("is_malicious")]
            return jsonify(threats[-10:])

        @self.app.route("/api/blocked_ips")
        def api_blocked_ips():
            return jsonify({"blocked_ips": sorted(list(getattr(proxy, "blocked_ips", []))), "count": len(getattr(proxy, "blocked_ips", []))})

        @self.app.route("/api/unblock_ip", methods=["POST"])
        def api_unblock_ip():
            ip = (request.json or {}).get("ip")
            if ip in getattr(proxy, "blocked_ips", set()):
                proxy.blocked_ips.remove(ip)
                try:
                    self.waf_logger.log_system_event("ip_unblocked", {"ip": ip}, severity="INFO")
                except Exception:
                    self.logger.exception("Failed to log unblock event")
                return jsonify({"status": "success", "ip": ip})
            return jsonify({"status": "failure", "reason": "IP not found"}), 404

        @self.app.route("/api/recent_url_verdicts")
        def api_recent_url_verdicts():
            return jsonify(list(reversed(list(recent_url_verdicts))))


    def run(self, host="0.0.0.0", port=API_PORT, debug=True):
        print(f"[INFO] Starting WAF API server on {host}:{port}")
        # Don't use reloader with threaded contexts
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)


# ---------------------------
# Helpers (testing & synthetic)
# ---------------------------
def generate_synthetic_data(num_samples=500):
    for _ in range(num_samples):
        ip = f"192.168.0.{random.randint(1, 254)}"
        bad = random.random() < 0.1
        try:
            proxy.record_request(ip, bad)
        except Exception:
            proxy.request_log = getattr(proxy, "request_log", [])
            proxy.request_log.append({"ip": ip, "is_malicious": bad, "ts": datetime.now().timestamp()})


def test_accuracy(test_dataset_path: str):
    import requests

    def sanitize(d):
        if isinstance(d, dict):
            return {k: sanitize(v) for k, v in d.items()}
        if isinstance(d, list):
            return [sanitize(x) for x in d]
        if isinstance(d, float):
            if math.isnan(d) or math.isinf(d):
                return 0.0
        return d

    def evaluate_model_properly(y_true, y_pred, y_proba):
        metrics = {
            "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
            "f1_score": f1_score(y_true, y_pred),
            "roc_auc": roc_auc_score(y_true, y_proba) if len(np.unique(y_true)) > 1 else float("nan"),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
        }
        print("Proper evaluation metrics:")
        for metric, value in metrics.items():
            print(f"{metric}: {value:.4f}" if not (isinstance(value, float) and math.isnan(value)) else f"{metric}: NaN")
        return metrics

    print(f"Testing dataset: {test_dataset_path}")
    df = pd.read_csv(test_dataset_path)
    y_true, y_pred, y_proba = [], [], []

    for i, row in df.iterrows():
        try:
            headers = row.get("headers", {})
            if isinstance(headers, str):
                try:
                    headers = json.loads(headers) if headers.strip() else {}
                except Exception:
                    headers = {}
            payload = {
                "method": row.get("method", "GET"),
                "url": row.get("url", ""),
                "payload": row.get("payload", ""),
                "headers": headers,
            }
            payload = sanitize(payload)
            r = requests.post(f"http://localhost:{API_PORT}/api/classify", json=payload, timeout=10)
            if not r.text.strip():
                raise ValueError("Empty response from server")

            result = r.json()
            actual = int(row.get("is_malicious", 0))
            pred = int(result.get("is_malicious", 0))
            prob = float(result.get("confidence", 0.0))

            y_true.append(actual)
            y_pred.append(pred)
            y_proba.append(prob)
        except Exception as e:
            print(f"Row {i} failed: {e}")
            y_true.append(int(row.get("is_malicious", 0)))
            y_pred.append(-1)
            y_proba.append(0.0)

    # Filter to valid preds 0/1
    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred)
    valid_mask = np.isin(y_pred_arr, [0, 1])

    if not valid_mask.any():
        print("[ERROR] No valid predictions collected.")
        return

    y_true_filtered = y_true_arr[valid_mask]
    y_pred_filtered = y_pred_arr[valid_mask]
    y_proba_filtered = np.array(y_proba)[valid_mask]

    acc = accuracy_score(y_true_filtered, y_pred_filtered) * 100
    print(f"\nModel Accuracy: {acc:.2f}%")
    print("Confusion matrix:")
    print(confusion_matrix(y_true_filtered, y_pred_filtered, labels=[0, 1]))
    evaluate_model_properly(y_true_filtered, y_pred_filtered, y_proba_filtered)
    print(classification_report(y_true_filtered, y_pred_filtered, labels=[0, 1], target_names=["Benign", "Malicious"]))


# ---------------------------
# Main
# ---------------------------
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

    # load or train model
    if not MODEL_PATH.exists():
        df = create_balanced_training_data()
        records, y = prepare_training_data(df)
        if len(records) == 0:
            print("[ERROR] No training records available. Exiting.")
            return

        extractor = FeatureExtractor()
        X = [WAFAPIServer(extractor, None, None)._prepare_vec(extractor.extract_features(r)) for r in records]
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

        model = HybridWAFModel()
        model.train(X_train, y_train)

        try:
            CONFIDENCE_THRESHOLD = find_optimal_threshold(model, X_val, y_val)
            print(f"[INFO] Adjusted threshold for imbalanced data: {CONFIDENCE_THRESHOLD:.3f}")
        except Exception:
            CONFIDENCE_THRESHOLD = 0.4
            print(f"[WARN] Using conservative threshold: {CONFIDENCE_THRESHOLD}")

        model.save_model(MODEL_PATH)
        MODEL_PATH.with_suffix(".threshold").write_text(str(CONFIDENCE_THRESHOLD))
    else:
        model = HybridWAFModel.load_model(MODEL_PATH)
        extractor = FeatureExtractor()
        threshold_file = MODEL_PATH.with_suffix(".threshold")
        if threshold_file.exists():
            try:
                CONFIDENCE_THRESHOLD = float(threshold_file.read_text().strip())
                print(f"[INFO] Loaded saved ML threshold: {CONFIDENCE_THRESHOLD:.3f}")
            except Exception:
                print("[WARN] Failed to parse threshold file; using default threshold.")
        else:
            print(f"[WARN] No saved threshold found. Using default {CONFIDENCE_THRESHOLD}")

    api = WAFAPIServer(extractor, model, waf_logger)

    if args.test_dataset:
        # run server in background thread then test
        threading.Thread(target=lambda: api.run(), daemon=True).start()
        # small wait to let server start
        time.sleep(2)
        test_accuracy(args.test_dataset)
        return

    if not args.no_server:
        api.run()


if __name__ == "__main__":
    if threading.current_thread() == threading.main_thread():
        signal.signal(signal.SIGINT, signal_handler)
    main()
