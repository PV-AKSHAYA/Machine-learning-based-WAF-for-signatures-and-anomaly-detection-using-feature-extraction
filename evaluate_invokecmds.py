import re
import json
import requests
import pandas as pd
from sklearn.metrics import (
    accuracy_score, confusion_matrix, classification_report,
    roc_auc_score, balanced_accuracy_score, f1_score, precision_score, recall_score
)

# ---------------- CONFIG ----------------
invokefile = "invokecmds.txt"           # File with Invoke-RestMethod commands
datasetfile = "waf_test_dataset_balanced_final.csv"     # Your dataset with true labels
api_url = "http://localhost:5001/api/classify"

# -----------------------------------------
# Load dataset for true labels lookup
df = pd.read_csv(datasetfile)

# Normalize URL strings for matching
df['url'] = df['url'].astype(str).str.strip()

# Load Invoke-RestMethod lines
with open(invokefile, "r", encoding="utf-16") as f:
    lines = [l.strip() for l in f if l.strip()]

y_true, y_pred, y_probs = [], [], []

for line in lines:
    # Extract JSON body from PowerShell command
    match = re.search(r"-Body\s+'({.*})'", line)
    if not match:
        print(f"[WARN] Could not parse line: {line}")
        continue

    try:
        body_str = match.group(1)
        body = json.loads(body_str)

        method = body.get("method", "GET")
        url = body.get("url", "").strip()
        payload = body.get("payload", "")
        headers = body.get("headers", {})

        # Look up true label from dataset
        # This assumes URL in dataset matches URL in Invoke-RestMethod
        true_label_row = df[df['url'].str.strip() == url]
        if true_label_row.empty:
            print(f"[WARN] No matching label found for URL: {url}")
            continue
        true_label = int(true_label_row['is_malicious'].values[0])

        # Send request to WAF API
        api_payload = {
            "method": method,
            "url": url,
            "payload": payload,
            "headers": headers
        }
        r = requests.post(api_url, json=api_payload, timeout=10)
        result = r.json()

        pred_label = int(result.get("is_malicious", 0))
        prob_val = float(result.get("confidence", 0))

        y_true.append(true_label)
        y_pred.append(pred_label)
        y_probs.append(prob_val)

    except Exception as e:
        print(f"[ERROR] Failed processing line: {line}\n{e}")

# ----------------- METRICS -----------------
print("\n=== EVALUATION METRICS ===")
print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
print(f"Balanced Accuracy: {balanced_accuracy_score(y_true, y_pred):.4f}")
print(f"F1 Score: {f1_score(y_true, y_pred):.4f}")
print(f"Precision: {precision_score(y_true, y_pred):.4f}")
print(f"Recall: {recall_score(y_true, y_pred):.4f}")

# Only compute ROC AUC if both classes present
if len(set(y_true)) > 1:
    print(f"ROC AUC: {roc_auc_score(y_true, y_probs):.4f}")
else:
    print("ROC AUC: Only one class present")

print("\nConfusion Matrix:")
print(confusion_matrix(y_true, y_pred))

print("\nClassification Report:")
print(classification_report(y_true, y_pred, target_names=["Benign", "Malicious"]))
