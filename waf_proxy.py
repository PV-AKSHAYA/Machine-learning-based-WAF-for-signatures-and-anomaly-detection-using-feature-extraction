import time
from typing import List, Dict, Any

class WAFProxy:
    def __init__(self):
        """
        Initialize the WAFProxy with an empty request log.
        """
        self.request_log: List[Dict[str, Any]] = []

    def log_request(self, is_malicious: bool,request_data:dict,feature_vector:dict):
        """
        Add a request log entry.

        Args:
            features (dict): Dictionary of feature_name -> value, e.g., from FeatureExtractor.
            is_malicious (bool): True if the request is considered malicious, False otherwise.
        """
        entry = {
            'request': request_data,
            'timestamp': time.time(),  # Unix timestamp (float)
            'features': feature_vector,      # Features as dict expected by ML model
            'is_malicious': is_malicious
        }
        self.request_log.append(entry)

    def get_recent_logs(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Retrieve logs from the last 'hours' hours.

        Args:
            hours (int): Number of hours back to fetch logs for.

        Returns:
            List[dict]: List of log entries newer than cutoff time.
        """
        cutoff = time.time() - (hours * 3600)
        # Return a copy to prevent external modification
        return [log.copy() for log in self.request_log if log['timestamp'] > cutoff]

    def clear_logs(self):
        """
        Clear all stored logs.

        Warning: Use with caution in production as this deletes all logged data.
        """
        self.request_log.clear()
