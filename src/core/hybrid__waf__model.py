import numpy as np
import re
import math
import json
from collections import Counter
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import joblib
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import precision_recall_curve
import pandas as pd


# ---------------- Feature Extractor ------------------
class FeatureExtractor:
    """
    Extracts numeric, statistical, and attack-pattern features from HTTP request data,
    including regex-based signature detection, and heuristic detections for
    DDoS, brute force, DoS, and port scanning.
    """
    def __init__(self, settings: dict | None = None):
        self.settings = settings or {}

        self.sql_keywords = [
            'union', 'select', 'from', 'where', 'insert', 'delete', 'update',
            'drop', 'create', 'alter', 'exec', 'execute', 'script', 'declare',
            'cast', 'convert', 'or', 'and', 'xor', 'waitfor', 'delay'
        ]
        self.xss_patterns = [
            r'<script.*?>.*?</script>', r'javascript:', r'on\w+\s*=', r'<iframe.*?>',
            r'<object.*?>', r'alert\s*\(', r'document\.cookie',
            r'onerror\s*=', r'onload\s*='
        ]
        self.command_patterns = [
            r';\s*(ls|cat|pwd|whoami|id|uname|rm|chmod|chown|curl|wget|nc|netcat|bash|sh)',
            r'\|\s*(ls|cat|pwd|whoami|id|uname|rm|chmod|chown|curl|wget|nc|netcat|bash|sh)',
            r'&&\s*(ls|cat|pwd|whoami|id|uname|rm|chmod|chown|curl|wget|nc|netcat|bash|sh)',
            r'`.*?`', r'\$\(.+?\)'
        ]
        self.suspicious_special_chars = [';', '|', '&', '`', '$', '<', '>', '\\']

        self.sql_regexes = [
            r"(?i)(\bUNION\b.*\bSELECT\b)", r"(?i)(\bOR\b\s+1=1)",
            r"(--|\#|/\*)\s*$", r"(?i)(\bDROP\b\s+\bTABLE\b)",
            r"(?i)(\bSELECT\b.*\bFROM\b)", r"(\bINSERT\b.*\bINTO\b)"
        ]
        self.xss_regexes = [
            r"<script.*?>.*?</script.*?>", r"onerror\s*=", r"onload\s*=",
            r"<img.*?src\s*=.*?>", r"javascript:", r"<.*?(alert|prompt|confirm)\s*\(.*?\)>"
        ]
        self.path_traversal_regexes = [r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c"]
        self.cmdinj_regexes = [r";\s*\w+", r"&&\s*\w+", r"`\s*\w+", r"\|\s*\w+"]
        self.ddos_keywords = ["hulk", "slowloris", "ping", "flood", "dos"]
        self.bruteforce_paths = [r"/login", r"/admin", r"/wp-login.php", r"/user/login"]
        self.bruteforce_password_patterns = [
            r"123456", r"password", r"admin", r"letmein", r"qwerty", r"abc123", r"password1"
        ]
        self.portscan_patterns = [r"port=\d+", r":\d{2,5}", r"scan", r"nmap", r"masscan"]

    def extract_features(self, request: dict) -> dict:
        url = request.get('url', '')
        headers = request.get('headers', {})
        payload = request.get('payload', '')

        features = {}
        features.update(self._extract_url_features(url))
        features.update(self._extract_header_features(headers))
        features.update(self._extract_payload_features(payload))
        features.update(self._extract_attack_features(url, payload, headers))

        combined_text = f"{url} {payload} {json.dumps(headers)}".lower()

        features['sqli_signature_count'] = self._count_signature_matches(combined_text, self.sql_regexes)
        features['xss_signature_count'] = self._count_signature_matches(combined_text, self.xss_regexes)
        features['path_traversal_signature_count'] = self._count_signature_matches(combined_text, self.path_traversal_regexes)
        features['cmdinj_signature_count'] = self._count_signature_matches(combined_text, self.cmdinj_regexes)

        features['ddos_signature_count'] = self._count_keyword_matches(combined_text, self.ddos_keywords)
        features['bruteforce_path_count'] = self._count_signature_matches(url.lower(), self.bruteforce_paths)
        features['bruteforce_password_count'] = self._count_signature_matches(payload.lower(), self.bruteforce_password_patterns)
        features['portscan_signature_count'] = self._count_signature_matches(combined_text, self.portscan_patterns)

        # Flags
        features['has_sqli_signature'] = int(features['sqli_signature_count'] > 0)
        features['has_xss_signature'] = int(features['xss_signature_count'] > 0)
        features['has_path_traversal_signature'] = int(features['path_traversal_signature_count'] > 0)
        features['has_cmdinj_signature'] = int(features['cmdinj_signature_count'] > 0)
        features['has_ddos_signature'] = int(features['ddos_signature_count'] > 0)
        features['has_bruteforce_path'] = int(features['bruteforce_path_count'] > 0)
        features['has_bruteforce_password'] = int(features['bruteforce_password_count'] > 0)
        features['has_portscan_signature'] = int(features['portscan_signature_count'] > 0)

        features.update(self._extract_statistical_features(url, payload, headers))
        return features

    # --- helper methods ---
    def _extract_url_features(self, url):
        if not url:
            return {k: 0 for k in [
                'url_length', 'path_length', 'query_length', 'fragment_length',
                'param_count', 'path_depth', 'has_query', 'has_fragment',
                'url_entropy', 'suspicious_chars_count', 'path_traversal_count'
            ]}
        p = urlparse(url)
        q = parse_qs(p.query)
        return {
            'url_length': len(url),
            'path_length': len(p.path),
            'query_length': len(p.query),
            'fragment_length': len(p.fragment or ''),
            'param_count': len(q),
            'path_depth': len([x for x in p.path.split('/') if x]),
            'has_query': int(bool(p.query)),
            'has_fragment': int(bool(p.fragment)),
            'url_entropy': self._calculate_entropy(url),
            'suspicious_chars_count': self._count_suspicious_chars(url),
            'path_traversal_count': url.count("../") + url.count("..\\"),
        }

    def _extract_header_features(self, headers):
        if not headers:
            return {k: 0 for k in [
                'header_count', 'user_agent_length', 'has_user_agent', 'has_referer',
                'has_cookie', 'content_type_length', 'header_entropy',
                'suspicious_headers'
            ]}
        ua = headers.get('User-Agent', '')
        ct = headers.get('Content-Type', '')
        return {
            'header_count': len(headers),
            'user_agent_length': len(ua),
            'has_user_agent': int(bool(ua)),
            'has_referer': int(bool(headers.get('Referer'))),
            'has_cookie': int(bool(headers.get('Cookie'))),
            'content_type_length': len(ct),
            'header_entropy': self._calculate_entropy(str(headers)),
            'suspicious_headers': sum(1 for h in headers if h.lower() in
                                      ['x-forwarded-for', 'x-real-ip', 'x-originating-ip'])
        }

    def _extract_payload_features(self, payload):
        if not payload:
            return {k: 0 for k in [
                'payload_length', 'payload_entropy', 'alpha_ratio', 'digit_ratio',
                'special_char_ratio', 'uppercase_ratio'
            ]}
        length = len(payload)
        return {
            'payload_length': length,
            'payload_entropy': self._calculate_entropy(payload),
            'alpha_ratio': sum(c.isalpha() for c in payload) / length,
            'digit_ratio': sum(c.isdigit() for c in payload) / length,
            'special_char_ratio': sum(not c.isalnum() for c in payload) / length,
            'uppercase_ratio': sum(c.isupper() for c in payload) / length,
        }

    def _extract_attack_features(self, url, payload, headers):
        text = f"{url} {payload} {json.dumps(headers)}".lower()
        return {
            'sql_keyword_count': sum(text.count(kw) for kw in self.sql_keywords),
            'xss_pattern_count': sum(len(re.findall(pat, text, re.IGNORECASE)) for pat in self.xss_patterns),
            'command_injection_count': sum(len(re.findall(pat, text, re.IGNORECASE)) for pat in self.command_patterns),
            'file_inclusion_count': len(re.findall(r'(file://|ftp://|http://)', text)),
            'encoded_chars_count': len(re.findall(r'%[0-9a-fA-F]{2}', text)),
        }

    def _extract_statistical_features(self, url, payload, headers):
        combined = f"{url} {payload} {json.dumps(headers)}"
        if not combined.strip():
            return {k: 0 for k in [
                'unique_char_count', 'most_common_char_freq', 'char_frequency_std',
                'whitespace_ratio', 'punctuation_density'
            ]}
        freq = Counter(combined)
        counts = list(freq.values())
        length = len(combined)
        avg_freq = sum(counts) / len(counts)
        variance = sum((c - avg_freq)**2 for c in counts) / len(counts)
        stddev = math.sqrt(variance if variance >= 0 else 0)
        return {
            'unique_char_count': len(freq),
            'most_common_char_freq': max(counts),
            'char_frequency_std': stddev,
            'whitespace_ratio': sum(c.isspace() for c in combined) / length,
            'punctuation_density': len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', combined)) / length,
        }

    def _calculate_entropy(self, s):
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())
        return entropy if math.isfinite(entropy) else 0.0

    def _count_suspicious_chars(self, text):
        return sum(text.count(ch) for ch in self.suspicious_special_chars)

    def _count_signature_matches(self, text, regex_list):
        count = 0
        for pattern in regex_list:
            try:
                if isinstance(pattern, str) and not any(c in pattern for c in ".*+?\\[]()^$"):
                    if pattern in text:
                        count += 1
                else:
                    if re.search(pattern, text, re.IGNORECASE):
                        count += 1
            except re.error:
                continue
        return count

    def _count_keyword_matches(self, text, keywords):
        return sum(1 for kw in keywords if kw in text)


# ------- HYBRID MODEL WITH CLEAR THRESHOLD LOGIC --------
class HybridWAFModel:
    def __init__(self, random_state=42, threshold=None):
        self.random_state = random_state
        self.rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            n_jobs=-1,
            random_state=random_state
        )
        self.gbm = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.05,
            max_depth=8,
            min_samples_split=10,
            subsample=0.8,
            random_state=random_state
        )
        self.best_threshold = threshold if threshold is not None else 0.5

    def train(self, X, y, augment_df: pd.DataFrame = None):
        # Check class distribution
        unique, counts = np.unique(y, return_counts=True)
        print(f"Class distribution: {dict(zip(unique, counts))}")

        # Handle imbalance
        if min(counts) / max(counts) < 0.1:
            from imblearn.over_sampling import ADASYN
            sm = ADASYN(random_state=self.random_state, n_neighbors=3)
        else:
            sm = SMOTE(random_state=self.random_state)

        X_res, y_res = sm.fit_resample(X, y)

        if augment_df is not None:
            print(f"[INFO] Augmenting training data with {len(augment_df)} synthetic benign samples")
            X_res = np.vstack([X_res, augment_df.drop(columns=["is_malicious"]).values])
            y_res = np.concatenate([y_res, augment_df["is_malicious"].values])

        print("[INFO] Starting Stratified 5-Fold Cross-Validation...")
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=self.random_state)
        thresholds, f1_scores = [], []

        for fold, (train_idx, val_idx) in enumerate(skf.split(X_res, y_res), 1):
            X_train, X_val = X_res[train_idx], X_res[val_idx]
            y_train, y_val = y_res[train_idx], y_res[val_idx]

            self.rf.fit(X_train, y_train)
            self.gbm.fit(X_train, y_train)

            probs = (self.rf.predict_proba(X_val)[:, 1] + self.gbm.predict_proba(X_val)[:, 1]) / 2
            precision, recall, thresh = precision_recall_curve(y_val, probs)
            f1_vals = 2 * (precision * recall) / (precision + recall + 1e-10)

            best_idx = np.argmax(f1_vals)
            thresholds.append(thresh[best_idx])
            f1_scores.append(f1_vals[best_idx])

            print(f"[Fold {fold}] Best F1: {f1_vals[best_idx]:.4f} @ Threshold {thresh[best_idx]:.4f}")

        self.best_threshold = float(np.mean(thresholds))
        print(f"[INFO] Optimal classification threshold set to {self.best_threshold:.4f} "
              f"(avg F1: {np.mean(f1_scores):.4f})")

        # Final training
        self.rf.fit(X_res, y_res)
        self.gbm.fit(X_res, y_res)

    def predict_proba(self, X):
        rf_prob = self.rf.predict_proba(X)[:, 1]
        gbm_prob = self.gbm.predict_proba(X)[:, 1]
        return (rf_prob + gbm_prob) / 2

    def predict(self, X, threshold=None):
        probs = self.predict_proba(X)
        use_thresh = self.best_threshold if threshold is None else threshold
        return (probs >= use_thresh).astype(int)

    def predict_verdict(self, X, threshold=None):
        labels = self.predict(X, threshold=threshold)
        return ['malicious' if l == 1 else 'benign' for l in labels]

    def save_model(self, path):
        joblib.dump(self, path)
        print(f"[INFO] Model saved to {path}")

    @classmethod
    def load_model(cls, path):
        return joblib.load(path)
