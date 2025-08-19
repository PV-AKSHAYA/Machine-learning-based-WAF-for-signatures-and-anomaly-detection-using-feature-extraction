import requests
import json
import re
from sklearn.metrics import (
    accuracy_score, confusion_matrix, classification_report,
    roc_auc_score, balanced_accuracy_score, f1_score, precision_score, recall_score
)

# File containing PowerShell Invoke-RestMethod commands
input_file = "invokecmds.txt"

# Define malicious keywords for auto-labeling (edit this list as needed)
malicious_keywords = [
    "bad.com", "malicious", "loginpage", "secure535.biz", "shoponline81.io",
    "secure533.us", "secure877.co", "shop306.io"
]

y_true = []
y_pred = []
y_probs = []

with open(input_file, "r", encoding="utf-16") as f:
    lines = [line.strip() for line in f if line.strip()]

for line in lines:
    # Match -Body '{...}' allowing spaces/newlines
    match = re.search(r"-Body\s+'(\{.*\})'", line, re.DOTALL)
    if match:
        try:
            body_str = match.group(1)
            body = json.loads(body_str)  # JSON already uses double quotes

            method = body.get("method", "GET")
            url = body.get("url", "")

            # Assign true label automatically
            true_label = 1 if any(keyword in url for keyword in malicious_keywords) else 0

            api_payload = {
                "method": method,
                "url": url,
                "payload": body.get("payload", ""),
                "headers": body.get("headers", {})
            }

            # Send to API
            try:
                r = requests.post(
                    "http://localhost:5001/api/classify",
                    json=api_payload,
                    timeout=10
                )
                result = r.json()
                y_pred.append(int(result.get("is_malicious", 0)))
                y_probs.append(result.get("confidence", 0))
                y_true.append(true_label)

            except requests.exceptions.RequestException as e:
                print(f"[ERROR] API request failed for {url}: {e}")

        except json.JSONDecodeError as e:
            print(f"[ERROR] JSON decode failed for line: {line}\n{e}")

    else:
        print("[WARN] Failed to parse line:", line)

# --- Metrics ---
if not y_true or not y_pred:
    print("[ERROR] No valid data parsed — check file format or regex.")
else:
    print("Accuracy:", accuracy_score(y_true, y_pred)*100,"%")
    print("Confusion Matrix:")
    print(confusion_matrix(y_true, y_pred))
    print("F1 Score:", f1_score(y_true, y_pred))
    print("Balanced Accuracy:", balanced_accuracy_score(y_true, y_pred))

    if len(set(y_true)) > 1:
        print("ROC AUC:", roc_auc_score(y_true, y_probs))
    else:
        print("ROC AUC: (only one class present)")

    print("Precision:", precision_score(y_true, y_pred, zero_division=0))
    print("Recall:", recall_score(y_true, y_pred, zero_division=0))
    print("Classification Report:")
    print(classification_report(
        y_true, y_pred, target_names=["Benign", "Malicious"], zero_division=0
    ))
