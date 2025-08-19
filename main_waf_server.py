from __future__ import annotations
import os
import ipaddress
import logging
import sys
from pathlib import Path
import threading
import signal
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_restful import Api, Resource
import pandas as pd
from collections import deque

import proxy  # You should have proxy.py exposing request_log and blocked_ips
from core.feature_extractor import FeatureExtractor
from core.hybrid__waf__model import HybridWAFModel  # updated model path
from advanced_waf_logger import AdvancedWAFLogger
from automated_updater import AutomatedModel  # Your automated retrain scheduler

# === Constants ===
BASE_DIR = Path(__file__).parent
CERT_FILE = BASE_DIR / "cert.pem"
KEY_FILE = BASE_DIR / "key.pem"
MODEL_PATH = BASE_DIR / "hybrid_waf_model.joblib"
CONFIDENCE_THRESHOLD = 0.75
LISTEN_HOST = ipaddress.IPv4Address("0.0.0.0")
LISTEN_PORT = 443
API_PORT = 5001

DATA_PATHS = [
    BASE_DIR / "waf_training_logs.csv",
    BASE_DIR / "bruteforce.csv",
    BASE_DIR / "dos.csv",
    BASE_DIR / "port_scaning.csv",
    BASE_DIR / "sqli.csv",
    BASE_DIR / "XSS.csv" ,
    BASE_DIR / "benign2.csv" ,
    BASE_DIR / "benign3.csv" ,
    BASE_DIR /  "benign4.csv",
    BASE_DIR / "benign5.csv"
]

MAX_RECENT_URLS = 50
recent_url_verdicts = deque(maxlen=MAX_RECENT_URLS)  # Store recent URL verdicts for dashboard

def signal_handler(signum, frame):
    print("Signal received, exiting...")
    sys.exit(0)

def read_csv_robust(filepath: Path) -> pd.DataFrame:
    try:
        df = pd.read_csv(filepath, on_bad_lines="skip")
        logging.info(f"Loaded CSV {filepath} (skip bad lines): {len(df)} rows")
        return df
    except TypeError:
        df = pd.read_csv(filepath, error_bad_lines=False, warn_bad_lines=True)
        logging.info(f"Loaded CSV {filepath} (error_bad_lines=False): {len(df)} rows")
        return df

def load_multiple_csv(files: list[Path]) -> pd.DataFrame:
    dfs = []
    for file in files:
        if file.exists():
            df = read_csv_robust(file)
            dfs.append(df)
        else:
            logging.warning(f"Dataset file {file} not found and will be skipped.")
    if dfs:
        combined_df = pd.concat(dfs, ignore_index=True)
        logging.info(f"Combined dataset contains {len(combined_df)} rows from {len(dfs)} files")
        return combined_df
    else:
        logging.error("No dataset files found.")
        return pd.DataFrame()

def prepare_training_data(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    df_clean = df.dropna()
    feature_cols = [c for c in df_clean.columns if c not in ("timestamp", "is_malicious")]
    X = df_clean[feature_cols].values
    y = df_clean["is_malicious"].values
    logging.info(f"Prepared training data: {X.shape[0]} samples, {X.shape[1]} features")
    return X, y

# --------------------- WAF API Server with Dashboard ------------------------
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

    def _setup_routes(self):
        class ClassifyRequest(Resource):
            def post(inner):
                try:
                    req = request.get_json()
                    if not req or not all(k in req for k in ("method", "url")):
                        return {"error": "Missing method or url"}, 400
                    feats = self.fe.extract_features(req)
                    if any([
                        feats.get('has_sqli_signature', 0),
                        feats.get('has_xss_signature', 0),
                        feats.get('has_path_traversal_signature', 0),
                        feats.get('has_cmdinj_signature', 0),
                        feats.get('has_ddos_signature', 0),
                        feats.get('has_bruteforce_path', 0),
                        feats.get('has_bruteforce_password', 0),
                        feats.get('has_portscan_signature', 0),
                    ]):
                        classification_result = {
                            "is_malicious": True,
                            "confidence": 1.0,
                            "threat_score": 100.0,
                            "classification": "malicious",
                            "detection_method": "signature-based",
                            "features": feats,
                            "timestamp": datetime.now().isoformat()
                        }
                    else:
                        vec = self._prepare_vec(feats)
                        prob = self.ml.predict_proba([vec])[0][1]
                        pred = bool(prob > CONFIDENCE_THRESHOLD)
                        classification_result = {
                            "is_malicious": pred,
                            "confidence": prob,
                            "threat_score": prob * 100,
                            "classification": "malicious" if pred else "benign",
                            "detection_method": "ml-based",
                            "features": feats,
                            "timestamp": datetime.now().isoformat()
                        }
                    self.waf_logger.log_request(
                        req,
                        classification_result,
                        action_taken="blocked" if classification_result["is_malicious"] else "allowed"
                    )
                    # Log recent URL verdict for real-time dashboard
                    recent_url_verdicts.append({
                        "url": req.get("url"),
                        "verdict": classification_result["classification"],
                        "timestamp": classification_result["timestamp"]
                    })
                    return classification_result
                except Exception as e:
                    self.logger.error(f"Classify error: {e}")
                    self.waf_logger.log_system_event("classification_failure", {"error": str(e)}, severity="ERROR")
                    return {"error": "Classification failed", "details": str(e)}, 500

        self.api.add_resource(ClassifyRequest, "/api/classify")

    def _setup_classify_url_route(self):
        @self.app.route("/api/classify_url", methods=["POST"])
        def classify_url():
            try:
                data = request.json
                url = data.get('url')
                if not url:
                    return jsonify({'error': 'No url provided'}), 400
                dummy_request_obj = {"method": "GET", "url": url}
                feats = self.fe.extract_features(dummy_request_obj)
                vec = self._prepare_vec(feats)
                prob = self.ml.predict_proba([vec])[0][1]
                verdict = "malicious" if prob > CONFIDENCE_THRESHOLD else "benign"
                timestamp = datetime.now().isoformat()
                # Log recent URL verdict for dashboard
                recent_url_verdicts.append({
                    "url": url,
                    "verdict": verdict,
                    "timestamp": timestamp
                })
                return jsonify({'url': url, 'verdict': verdict, 'confidence': prob, 'timestamp': timestamp})
            except Exception as e:
                return jsonify({'error': str(e)}), 500

    def _prepare_vec(self, feats: dict) -> list[float]:
        names = [
            "url_length", "path_length", "query_length", "param_count",
            "header_count", "payload_length", "sql_keyword_count",
            "xss_pattern_count", "command_injection_count", "path_traversal_count",
            "url_entropy", "payload_entropy", "alpha_ratio", "digit_ratio",
            "special_char_ratio", "suspicious_chars_count"
        ]
        return [feats.get(n, 0) for n in names]

    def _setup_dashboard_routes(self):
        @self.app.route("/")
        def home():
            return render_template("index.html")  # Your dashboard HTML

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
            sql_count = sum(1 for r in proxy.request_log if r.get("is_malicious") and "sql" in r.get("features", {}))
            return jsonify({
                "sql_injection": sql_count,
                "xss": 0,
                "command_injection": 0
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
            return jsonify(threats[-10:][::-1])

        @self.app.route("/api/blocked_ips")
        def api_blocked_ips():
            return jsonify({"blocked_ips": sorted(proxy.blocked_ips), "count": len(proxy.blocked_ips)})

        @self.app.route("/api/unblock_ip", methods=["POST"])
        def api_unblock_ip():
            ip = request.json.get("ip")
            if ip in proxy.blocked_ips:
                proxy.blocked_ips.remove(ip)
                self.waf_logger.log_system_event("ip_unblocked", {"ip": ip}, severity="INFO")
                return jsonify({"status": "success", "ip": ip})
            return jsonify({"status": "fail", "reason": "IP not found"}), 404

        @self.app.route("/api/threat_severity_chart")
        def api_threat_severity_chart():
            return jsonify({"low": 15, "medium": 7, "high": 3})

        @self.app.route("/api/recent_url_verdicts")
        def api_recent_url_verdicts():
            return jsonify(list(reversed(recent_url_verdicts)))

    def run(self, host="0.0.0.0", port=API_PORT, debug=True, use_reloader=False):
        self.waf_logger.log_system_event("api_startup", {"host": host, "port": port}, severity="INFO")
        self.app.run(host=host, port=port, debug=debug, use_reloader=use_reloader)

def generate_synthetic_data(num_samples: int = 500) -> None:
    import random
    import time
    for _ in range(num_samples):
        ip = f"192.168.0.{random.randint(1, 254)}"
        bad = random.random() < 0.1  # 10% malicious
        proxy.record_request(ip, bad)

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    logger = logging.getLogger("main_waf_server")
    waf_logger = AdvancedWAFLogger()
    waf_logger.log_system_event("server_startup", {"message": "WAF server starting"}, severity="INFO")

    if not MODEL_PATH.exists():
        logger.info(f"No model at {MODEL_PATH}, training...")
        waf_logger.log_system_event("training_start", {"model_path": str(MODEL_PATH)}, severity="INFO")
        df = load_multiple_csv(DATA_PATHS)
        if df.empty:
            logger.error("No training data available after loading datasets. Exiting.")
            waf_logger.log_system_event("training_failure", {"error": "No training data available."}, severity="CRITICAL")
            sys.exit(1)
        try:
            X, y = prepare_training_data(df)
            model = HybridWAFModel()
            model.train(X, y)
            model.save_model(MODEL_PATH)
            logger.info("Model trained and saved")
            waf_logger.log_model_update({
                "old_accuracy": 0.0,
                "new_accuracy": model.accuracy if hasattr(model, 'accuracy') else 0.0,
                "improvement": 0.0,
                "samples_used": len(X),
                "success": True,
                "timestamp": datetime.now().isoformat()
            })
        except Exception:
            logger.exception("Training failed")
            waf_logger.log_system_event("training_failure", {"error": "Exception during training"}, severity="CRITICAL")
            sys.exit(1)
    else:
        try:
            model = HybridWAFModel.load_model(MODEL_PATH)
            logger.info("Model loaded")
            waf_logger.log_system_event("model_loaded", {"model_path": str(MODEL_PATH)}, severity="INFO")
        except Exception:
            logger.exception("Loading model failed")
            waf_logger.log_system_event("model_load_failure", {"error": "Exception during model loading"}, severity="CRITICAL")
            sys.exit(1)

    extractor = FeatureExtractor()
    if len(proxy.request_log) < 500:
        logger.info("[startup] generating synthetic data …")
        generate_synthetic_data(600)
        logger.info("[startup] synthetic data ready.")

    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        logger.info(f"Starting HTTPS proxy on {LISTEN_HOST}:{LISTEN_PORT}")
        waf_logger.log_system_event("proxy_startup", {"host": str(LISTEN_HOST), "port": LISTEN_PORT}, severity="INFO")
        def run_proxy():
            try:
                proxy.main(
                    feature_extractor=extractor,
                    ml_model=model,
                    port=LISTEN_PORT,
                    cert_file=str(CERT_FILE),
                    key_file=str(KEY_FILE),
                    ca_cert_file=str(BASE_DIR / "cert.crt"),
                    ca_signing_key_file=str(BASE_DIR / "ca.key"),
                    confidence_threshold=CONFIDENCE_THRESHOLD,
                    hostname=LISTEN_HOST
                )
            except Exception as e:
                waf_logger.log_system_event("proxy_failure", {"error": str(e)}, severity="CRITICAL")
                logger.error(f"Proxy failed: {e}")
        threading.Thread(target=run_proxy, daemon=True).start()

    try:
        automated_updater = AutomatedModel(
            waf_proxy=proxy,
            ml_model=model,
            feature_extractor=extractor,
            waf_logger=waf_logger
        )
        logger.info("Automated model updater started.")
    except Exception as e:
        logger.error(f"Failed to start automated model updater: {e}")

    logger.info(f"Starting REST API and Dashboard on port {API_PORT}")
    api = WAFAPIServer(extractor, model, waf_logger=waf_logger)
    api.run(use_reloader=False)

if __name__ == "__main__":
    if threading.current_thread() == threading.main_thread():
        signal.signal(signal.SIGINT, signal_handler)
    main()
