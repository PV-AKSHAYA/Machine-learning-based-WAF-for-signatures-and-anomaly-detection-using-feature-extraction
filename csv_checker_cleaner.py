import pandas as pd
import json
import html

INPUT_FILE = "waf_test_dataset_balanced_final.csv"       # your original pasted dataset file
OUTPUT_FILE = "cleaned_dataset.csv"

def parse_headers(h):
    # Ensure headers always end up as valid JSON dict string
    if pd.isna(h):
        return "{}"
    if isinstance(h, dict):
        return json.dumps(h)
    if isinstance(h, str):
        try:
            parsed = json.loads(h)
            if isinstance(parsed, dict):
                return json.dumps(parsed)
        except json.JSONDecodeError:
            pass
    return "{}"

# Load CSV
df = pd.read_csv(INPUT_FILE)

# Decode HTML entities in URL and payload
for col in ["url", "payload"]:
    if col in df.columns:
        df[col] = df[col].apply(lambda x: html.unescape(x) if isinstance(x, str) else x)

# Ensure headers are valid JSON strings
df["headers"] = df["headers"].apply(parse_headers)

# Remove any obvious paste artifacts
df = df.dropna(subset=["method", "url"])
df = df[~df["method"].astype(str).str.contains(r"\.\.\.")]

# Ensure is_malicious is integer
df["is_malicious"] = df["is_malicious"].astype(int)

# Save cleaned CSV
df.to_csv(OUTPUT_FILE, index=False)
print(f"[INFO] Cleaned dataset saved to {OUTPUT_FILE}")
