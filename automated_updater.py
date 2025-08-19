import schedule
import threading
import time
from datetime import datetime
from sklearn.model_selection import cross_val_score
import numpy as np
import logging


class AutomatedModel:
    def __init__(self, waf_proxy, ml_model, feature_extractor, waf_logger=None):
        """
        Initialize the Automated Model Updater.

        Args:
            waf_proxy: Instance with .request_log attribute (list of dict logs).
            ml_model: ML model instance with train, predict, save_model, is_trained, meta_classifier attributes.
            feature_extractor: FeatureExtractor instance (if needed).
            waf_logger: Optional AdvancedWAFLogger instance for logging events.
        """
        self.logger = logging.getLogger("AutomatedModel")
        self.waf_proxy = waf_proxy
        self.ml_model = ml_model
        self.feature_extractor = feature_extractor
        self.waf_logger = waf_logger

        # Configuration
        self.retraining_threshold = 0.05      # Retrain if accuracy drops by 5%
        self.min_improvement = 0.01            # Deploy only if retrained accuracy > current + 1%
        self.last_accuracy = 0.0
        self.retraining_interval_hours = 24
        self.min_new_samples = 100

        # Validation thresholds
        self.min_samples_per_class = 200
        self.recommended_total_samples = 1000
        self.balance_range = (0.2, 0.8)  # acceptable class ratio range

        # Schedule periodic retraining
        schedule.every(self.retraining_interval_hours).hours.do(self._scheduled_retrain)

        # Start scheduler thread
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()

        self.logger.info("AutomatedModel updater started, scheduled every "
                         f"{self.retraining_interval_hours} hours")

    def _run_scheduler(self):
        """Run scheduled jobs in a loop."""
        while True:
            schedule.run_pending()
            time.sleep(60)

    def _scheduled_retrain(self):
        """Fetch new data, validate, retrain model if improved, and deploy."""
        now = datetime.now()
        self.logger.info(f"[{now}] Starting scheduled model retraining...")

        data = self._gather_new_data()
        n_samples = len(data['X']) if data else 0
        if not data or n_samples < self.min_new_samples:
            self.logger.info(f"Insufficient new samples ({n_samples}). Skipping retraining.")
            return

        # Validate dataset adequacy
        validation = self._validate_data_adequacy(data)
        if not validation['proceed']:
            self.logger.warning(f"Skipping retraining: {validation['reason']}")
            return
        for warning in validation.get('warnings', []):
            self.logger.warning(warning)

        # Evaluate current model
        current_acc = self._evaluate(self.ml_model, data)
        self.logger.info(f"Current accuracy: {current_acc:.4f}")

        # Retrain and evaluate new model
        new_model = self._retrain(data)
        new_acc = self._evaluate(new_model, data)
        self.logger.info(f"Retrained accuracy: {new_acc:.4f}")

        if new_acc > current_acc + self.min_improvement:
            self.ml_model = new_model
            self.last_accuracy = new_acc
            self._save_model_version()
            self.logger.info("Model updated to improved version.")
            if self.waf_logger:
                self.waf_logger.log_model_update({
                    "old_accuracy": current_acc,
                    "new_accuracy": new_acc,
                    "improvement": new_acc - current_acc,
                    "samples_used": len(data['X']),
                    "success": True,
                    "timestamp": now.isoformat()
                })
        else:
            self.logger.info("No significant improvement; keeping existing model.")

    def _gather_new_data(self):
        """Collect and prepare logs from the last 24 hours."""
        cutoff = time.time() - 24 * 3600
        try:
            recent = [log for log in self.waf_proxy.request_log if log.get('timestamp', 0) > cutoff]
        except Exception as e:
            self.logger.error(f"Error accessing waf_proxy.request_log: {e}")
            return None

        if len(recent) < self.min_new_samples:
            return None

        X, y = [], []
        for log in recent:
            vec = self._vectorize(log.get('features', {}))
            X.append(vec)
            y.append(1 if log.get('is_malicious', False) else 0)
        return {'X': np.array(X), 'y': np.array(y)}

    def _vectorize(self, features: dict) -> list:
        """Convert feature dict to ordered vector."""
        keys = [
            'url_length', 'path_length', 'query_length', 'param_count',
            'header_count', 'payload_length', 'sql_keyword_count',
            'xss_pattern_count', 'command_injection_count', 'path_traversal_count',
            'url_entropy', 'payload_entropy', 'alpha_ratio', 'digit_ratio',
            'special_char_ratio', 'suspicious_chars_count'
        ]
        return [features.get(k, 0) for k in keys]

    def _evaluate(self, model, data: dict) -> float:
        """Compute accuracy or cross-validated accuracy on data."""
        X, y = data['X'], data['y']
        if len(X) < 5 or len(np.unique(y)) < 2:
            preds = model.predict(X)
            return float(np.mean(preds == y)) if len(X) > 0 else 0.0

        class_counts = np.bincount(y)
        min_class_count = class_counts.min()
        cv_folds = min(5, min_class_count) if min_class_count >= 2 else 2

        scores = cross_val_score(model.meta_classifier, X, y, cv=cv_folds, scoring='accuracy')
        return float(np.mean(scores))

    def _retrain(self, data: dict):
        """Retrain a fresh model instance on new + historical data."""
        new_model = type(self.ml_model)()
        X_train, y_train = data['X'], data['y']

        hist = self._gather_historical_data()
        if hist:
            X_train = np.vstack([X_train, hist['X']])
            y_train = np.concatenate([y_train, hist['y']])

        new_model.train(X_train, y_train)
        return new_model

    def _gather_historical_data(self, max_samples=1000):
        """Fetch up to max_samples older than 24h for stability."""
        cutoff = time.time() - 24 * 3600
        try:
            old_logs = [log for log in self.waf_proxy.request_log if log.get('timestamp', 0) <= cutoff]
        except Exception as e:
            self.logger.error(f"Error accessing waf_proxy.request_log for historical data: {e}")
            return None

        if not old_logs:
            return None
        if len(old_logs) > max_samples:
            idx = np.random.choice(len(old_logs), max_samples, replace=False)
            old_logs = [old_logs[i] for i in idx]

        X, y = [], []
        for log in old_logs:
            vec = self._vectorize(log.get('features', {}))
            X.append(vec)
            y.append(1 if log.get('is_malicious', False) else 0)
        return {'X': np.array(X), 'y': np.array(y)}

    def _validate_data_adequacy(self, data: dict) -> dict:
        """
        Validate that training data meets minimum requirements before retraining.

        Returns:
            dict:
              - proceed (bool): whether to run retraining
              - reason (str): if not proceeding, why
              - warnings (List[str]): non-fatal issues to log
        """
        X, y = data['X'], data['y']
        total = len(X)
        pos = int(y.sum())
        neg = total - pos

        result = {'proceed': True, 'reason': '', 'warnings': []}

        # Hard stop: minimum per-class requirement
        if pos < self.min_samples_per_class or neg < self.min_samples_per_class:
            result['proceed'] = False
            result['reason'] = (
                f"Insufficient samples per class (need ≥{self.min_samples_per_class}). "
                f"Have {pos} malicious, {neg} benign."
            )
            return result

        # Non-fatal: small total dataset
        if total < self.recommended_total_samples:
            result['warnings'].append(
                f"Dataset small ({total} samples). Recommend ≥{self.recommended_total_samples}."
            )

        # Non-fatal: class imbalance
        ratio = pos / total if total > 0 else 0
        low, high = self.balance_range
        if ratio < low or ratio > high:
            result['warnings'].append(
                f"Class imbalance detected (malicious {ratio:.1%}). Aim for {int(low*100)}–{int(high*100)}%."
            )

        return result

    def _save_model_version(self):
        """Persist current model with timestamped filename."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"waf_model_v{ts}.joblib"
        self.ml_model.save_model(filename)
        self.logger.info(f"Saved new model as {filename}")

    def trigger_immediate_retrain(self):
        """Expose manual retrain trigger."""
        self.logger.info("Manual retraining triggered...")
        self._scheduled_retrain()

    def get_model_info(self) -> dict:
        """Return metadata about current model and schedule."""
        next_run = schedule.next_run() if schedule.get_jobs() else None
        return {
            'last_accuracy': self.last_accuracy,
            'is_trained': getattr(self.ml_model, 'is_trained', False),
            'next_scheduled_retrain': next_run,
            'retraining_threshold': self.retraining_threshold
        }
