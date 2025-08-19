import threading
import time

# Shared logs and IP sets
request_log = []
blocked_ips = set()

lock = threading.Lock()

def record_request(ip: str, is_malicious: bool):
    with lock:
        entry = {
            "ip": ip,
            "is_malicious": is_malicious,
            "ts": time.time()  # Unix timestamp
        }
        request_log.append(entry)
        if is_malicious:
            blocked_ips.add(ip)

def get_statistics():
    with lock:
        total = len(request_log)
        blocked = sum(1 for r in request_log if r.get("is_malicious"))
        unique = len(blocked_ips)
        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "unique_blocked_ips": unique
        }

# Dummy proxy main function to simulate proxy running
def main(feature_extractor, ml_model, port, cert_file, key_file,
         ca_cert_file, ca_signing_key_file, confidence_threshold, hostname):
    print(f"Starting dummy proxy on {hostname}:{port}...")
    try:
        while True:
            # Simulate receiving requests and recording them
            import random
            ip = f"192.168.1.{random.randint(2,254)}"
            is_malicious = random.random() < 0.1  # 10% chance malicious
            record_request(ip, is_malicious)
            time.sleep(1)  # simulate 1 request per second
    except KeyboardInterrupt:
        print("Proxy stopped by user")
