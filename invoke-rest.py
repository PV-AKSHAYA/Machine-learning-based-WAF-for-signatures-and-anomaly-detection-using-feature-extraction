import pandas as pd
import json

# Load your CSV (paste.txt)
df = pd.read_csv("waf_test_dataset_balanced_final.csv")

for _, row in df.iterrows():
    method = row['method']
    url = row['url']
    payload = row['payload'] if pd.notnull(row['payload']) else ""
    headers = row['headers']
    
    # Ensure headers are passed as JSON object (string in Invoke-RestMethod)
    body = {
        "method": method,
        "url": url,
        "payload": payload,
        "headers": json.loads(headers) if headers and headers.strip() else {}
    }
    
    # PowerShell command output
    print(
        f"Invoke-RestMethod -Uri http://localhost:5001/api/classify "
        f"-Method POST -ContentType 'application/json' "
        f"-Body '{json.dumps(body)}'"
    )
