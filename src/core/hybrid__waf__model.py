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
