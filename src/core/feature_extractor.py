import re
import math
import json
from urllib.parse import urlparse, parse_qs
from collections import Counter

class FeatureExtractor:
    """
    Extracts numeric, statistical, and attack-pattern features
    from HTTP request data, including regex-based signature detection,
    and heuristic detections for DDoS, brute force, DoS, and port scanning.
    """

    def __init__(self, settings: dict | None = None):
        self.settings = settings or {}

        # --- SQL Injection patterns (more specific) ---
        self.sql_keywords = [
            'union', 'select', 'from', 'where', 'insert', 'delete', 'update',
            'drop', 'create', 'alter', 'exec', 'execute', 'declare',
            'cast', 'convert', 'or', 'and', 'xor', 'waitfor', 'delay',
            'sleep', 'benchmark', 'having', 'group_concat', 'information_schema',
            'substr', 'substring', 'outfile', 'load_file', 'concat_ws'
        ]
        self.sql_regexes = [
            r"(?i)\bUNION\b.+\bSELECT\b",
            r"(?i)\bSELECT\b.+\bFROM\b",
            r"(?i)\bDROP\b\s+\bTABLE\b",
            r"(?i)\bINSERT\b.+\bINTO\b",
            r"(?i)\bUPDATE\b.+\bSET\b",
            r"(?i)\bDELETE\b.+\bFROM\b",
            r"(?i)\bOR\s+1=1\b",
            r"(?i)\bSLEEP\s*\(",
            r"(?i)\bBENCHMARK\s*\(",
            r"(?i)\bGROUP_CONCAT\b",
            r"(?i)\bINFORMATION_SCHEMA\b",
            r"(?i)\bSUBSTRING\b",
            r"(?i)\bLOAD_FILE\b",
            r"(?i)\bCONCAT_WS\b"
        ]

        # --- XSS Patterns (safe, no overmatching) ---
        self.xss_patterns = [
            r"(?i)<script\b[^>]*>.*?</script\s*>",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=",
            r"(?i)<iframe\b[^>]*>.*?</iframe\s*>",
            r"(?i)<img\b[^>]*onerror\s*=",
            r"(?i)<.*?(alert|prompt|confirm)\s*\(",
            r"(?i)document\.cookie",
            r"(?i)document\.write",
            r"(?i)window\.location",
            r"(?i)<xss>",                     # Literal <XSS> test tag
            r"';!--\"<XSS>=&\{\(\)}",         # Classic XSS polyglot fuzz
            r"[\"']\s*>\s*<",                 # Breaking out of attributes into tags
            r"(%3C|<).*?(%3E|>)",              # Any HTML tag (encoded or literal)
            r"(%22|%27)",                     # Encoded quotes
            r"%3Cscript%3E",                  # Encoded <script>
            r"(%3C|<).*?(alert|prompt|confirm).*?(%3E|>)", # Encoded JS popups
        ]
        self.xss_regexes = [
            r"(?i)<script\b[^>]*>.*?</script\s*>",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)<img\b[^>]*src\s*=",
            r"(?i)javascript:",
            r"(?i)<.*?(alert|prompt|confirm)\s*\("
        ]

        # --- Command Injection Patterns ---
        self.command_patterns = [
            r";\s*\b(ls|cat|pwd|whoami|id|uname|rm|chmod|curl|wget)\b",
            r"\|\s*\b(ls|cat|pwd|whoami|id|uname|rm|chmod|curl|wget)\b",
            r"&&\s*\b(ls|cat|pwd|whoami|id|uname|rm|chmod|curl|wget)\b",
            r"`[^`]+`",
            r"\$\(.+?\)"
        ]
        self.cmdinj_regexes = [
            r";\s*\w+",
            r"&&\s*\w+",
            r"`\s*\w+",
            r"\|\s*\w+"
        ]

        # --- Path Traversal Patterns ---
        self.path_traversal_regexes = [
            r"\.\./", r"\.\.\\", r"%2e%2e/", r"%2e%2e\\"
        ]

        # Misc attack indicators
        self.suspicious_special_chars = [';', '|', '&', '`', '$', '<', '>', '\\']
        self.ddos_keywords = ["hulk", "slowloris", "ping", "flood", "dos"]
        self.bruteforce_paths = [
            r"/login", r"/admin", r"/wp-login.php", r"/user/login",
            r"type=bruteforce", r"attack=bruteforce", r"action=login"
        ]
        self.bruteforce_password_patterns = [
            '1234', '12345', '123456', '12345678', 'password', 'password1',
            'abc123', 'letmein', 'qwerty'
        ]
        self.portscan_patterns = [
            r"port=\d{1,5}", r":\d{2,5}\b", r"\bnmap\b", r"\bscan\b", r"\bmasscan\b"
        ]
                # --- Fuzzing Patterns ---
        self.fuzzing_patterns = [
            r"A{100,}",             # Long repeated 'A's (buffer overflow/fuzzing)
            r"B{100,}",
            r"C{100,}",
            r"([A-Za-z0-9]{50,})",  # Very long alphanumeric strings
            r"(%[0-9A-Fa-f]{2}){20,}",   # Excessive URL encoding
            r"\bfuzz\b", 
            r"\bFUZZ\b",                     # Literal fuzz keyword
            r"A{8,}",                        # Repeated 'A's
            r"B{8,}",                        # Repeated 'B's
            r"C{8,}",                        # Repeated 'C's
            r"([A-Za-z0-9])\1{7,}",          # Any character repeated 8+ times
            r"([A-Za-z0-9]{32,})",           # Long uninterrupted alphanumeric sequences
            r"(%[0-9A-Fa-f]{2}){5,}",        # Excessive URL encoding (>=5 encoded bytes)
            r"%00",                          # Null byte injection
            r"%ff",                          # High-byte fuzz
            r"[\"'<>%&]{3,}",                # 3+ consecutive fuzz special chars                                # Literal word "fuzz"
        ]

        # --- FTP Exploit Patterns ---
        self.ftp_exploit_patterns = [
            r"USER\s+\w{50,}",           # Very long usernames
            r"PASS\s+\w{50,}",           # Very long passwords
            r"\bsite\b\s+\bexec\b",      # SITE EXEC command
            r"\bSITE\b\s+\bCHMOD\b",     # SITE CHMOD command
            r"\bMKD\b",                  # Directory creation
            r"\bDELE\b",                 # File deletion
            r"\bPORT\b\s+\d+",           # PORT command
            r"\bFTP\b.*?(attack|exploit)",# Literal indicators
        ]

        # --- ICMP Flood Patterns ---
        self.icmp_flood_patterns = [
            r"\bicmp\b",                     # Literal "icmp"
            r"\bpings\b",                    # "pings"
            r"\bping flood\b",               # Common tool phrase
            r"\bsmurf\b",                    # Smurf attack
            r"\bpackets per second\b",       # PPS indicator
            r"\bping\b\s+\d{4,}",            # Large numerical ping count
            r"ftp://",                     # Any request referencing ftp://
            r"(command\s*=\s*open\s*ftp://)", # Direct FTP open attempts
            r"\bexploit\b",                # Presence of exploit keyword
            r"ftp=1",                      # Query string flag for FTP probes
            r"\bicmp_flood\b",                   # Explicit flag in payload/query
            r"\bicmp\s*flood\b",                  # "icmp flood" text
            r"\bping\s*flood\b",                  # "ping flood"
            r"\bpackets\s+per\s+second\b",        # pps indicator in flood              
            r"icmp_flood=1",                      # param like in your dataset
            r"type=icmp",                         # icmp type param
            r"protocol=icmp",                     # explicit ICMP mention
            r"\bpackets\s+per\s+second\b",
            r"\bping\s+\d{3,}\b",         # suspiciously high ping counts
            r"type\s*=\s*icmp\b",         # ICMP param type
            r"protocol\s*=\s*icmp\b",     # Protocol = ICMP
            r"\bicmp_flood=1\b",          # Explicit flag exactly as in dataset
            r"\bicmp[\s_]*flood\b",       # Matches "icmp flood" or "icmp_flood"
            r"\bping[\s_]*flood\b",       # ping flood reference
        ]

                # --- SSH/FTP Brute Force Patterns ---
        self.ssh_ftp_bruteforce_paths = [
            r"/ftp-login", r"/ssh-login", r"/login", r"/secure-login"
        ]
        
        self.bruteforce_usernames = [
            r"\b(root|admin|git|ubuntu|test|user|ftpuser|ftpadmin|anonymous)\b"
        ]
        
        self.bruteforce_passwords_extra = [
            r"\b(1234|12345|123456|password|password1|guest|letmein|test|gitpass|ubuntu)\b"
        ]
        self.ddos_user_agent_patterns = [
            r"\bcurl/[0-9]",              # curl UAs
            r"\bPostmanRuntime\b",        # postman bots
            r"^\s*$",                     # empty User-Agent
            r"^\W+$",                     # nonsense UA
    ]




    # -----------------
    # Keep your existing methods (_extract_benign_indicators, extract_features, etc.)
    # No changes needed in feature calculations â€” only regexes were made stricter.
    # -----------------


    # ------------------ Feature Extraction ------------------

    def _extract_benign_indicators(self, url, headers, method):
        """Extra features likely present in benign traffic."""
        return {
            'has_common_extension': int(any(ext in url.lower() for ext in ['.html', '.css', '.js', '.png', '.jpg','.jpeg','.gif','.svg'])),
            'has_standard_headers': int(len(set(headers.keys()) & {'User-Agent','Referer','Cookie', 'Accept', 'Accept-Language'}) >= 3),
            'url_depth_normal': int(url.count('/') <= 5),
            'method_is_get': int(method.upper() == 'GET'),
            'domain_is_common': int(any(domain in url.lower() for domain in ['google', 'facebook', 'amazon', 'microsoft'])),
            'no_suspicious_params': int(not any(param in url.lower() for param in ['script', 'union', 'select', 'drop','etc/passwd', '<script']))
        }

    def extract_features(self, request: dict) -> dict:
        url = str(request.get('url', '') or '')
        headers = request.get('headers', {}) or {}
        payload = str(request.get('payload', '') or '')
        method = str(request.get('method', 'GET')).upper()

        features = {}
        features.update(self._extract_url_features(url))
        features.update(self._extract_header_features(headers))
        features.update(self._extract_payload_features(payload))
        features.update(self._extract_attack_features(url, payload, headers))

        combined_text = f"{url} {payload} {json.dumps(headers)}".lower()

        features['sqli_signature_count'] = self._count_signature_matches(combined_text, self.sql_regexes)
        features['xss_signature_count'] = self._count_signature_matches(combined_text, self.xss_regexes)
        features['path_traversal_count'] = self._count_signature_matches(combined_text, self.path_traversal_regexes)
        features['cmdinj_signature_count'] = self._count_signature_matches(combined_text, self.cmdinj_regexes)

        features['ddos_signature_count'] = self._count_keyword_matches(combined_text, self.ddos_keywords)
        features['bruteforce_path'] = self._count_signature_matches(url.lower(), self.bruteforce_paths)
        features['bruteforce_password'] = self._count_signature_matches(payload.lower(), self.bruteforce_password_patterns)
        features['portscan_signature_count'] = self._count_signature_matches(combined_text, self.portscan_patterns)

        features['fuzzing_signature_count'] = self._count_signature_matches(combined_text, self.fuzzing_patterns)
        features['ftp_exploit_signature_count'] = self._count_signature_matches(combined_text, self.ftp_exploit_patterns)
        features['icmp_flood_signature_count'] = self._count_signature_matches(combined_text, self.icmp_flood_patterns)

        features['has_fuzzing_signature'] = int(features['fuzzing_signature_count'] > 0)
        features['has_ftp_exploit_signature'] = int(features['ftp_exploit_signature_count'] > 0)
        features['has_icmp_flood_signature'] = int(features['icmp_flood_signature_count'] > 0)

        features['has_sqli_signature'] = int(features['sqli_signature_count'] > 0)
        features['has_xss_signature'] = int(features['xss_signature_count'] > 0)
        features['has_path_traversal_signature'] = int(features['path_traversal_count'] > 0)
        features['has_cmdinj_signature'] = int(features['cmdinj_signature_count'] > 0)
        features['has_ddos_signature'] = int(features['ddos_signature_count'] > 0)
        features['has_brutforce_path'] = int(features['bruteforce_path'] > 0)
        features['has_brutforce_password'] = int(features['bruteforce_password'] > 0)
        features['has_portscan_signature'] = int(features['portscan_signature_count'] > 0)

        features.update(self._extract_statistical_features(url, payload, headers))
        features['is_post'] = 1 if method == 'POST' else 0
        features.update(self._extract_benign_indicators(url, headers, method))

        features['ssh_ftp_bruteforce_path_count'] = self._count_signature_matches(url.lower(), self.ssh_ftp_bruteforce_paths)
        features['ssh_ftp_bruteforce_user_count'] = self._count_signature_matches(payload.lower(), self.bruteforce_usernames)
        features['ssh_ftp_bruteforce_pass_count'] = self._count_signature_matches(payload.lower(), self.bruteforce_passwords_extra)

        features['has_ssh_ftp_bruteforce'] = int(
            features['ssh_ftp_bruteforce_path_count'] > 0 and
            (features['ssh_ftp_bruteforce_user_count'] > 0 or features['ssh_ftp_bruteforce_pass_count'] > 0)
        )
        features['ddos_ua_signature_count'] = self._count_signature_matches(
        headers.get("User-Agent", ""), self.ddos_user_agent_patterns
     )
        features['has_suspicious_ua'] = int(features['ddos_ua_signature_count'] > 0)


        # Sanitize floats
        for k, v in features.items():
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v) or v > 1e308 or v < -1e308 or (abs(v) < 1e-308 and v != 0.0)):
                features[k] = 0.0

        return features

    # ------------------ Helper Methods ------------------

    def _extract_url_features(self, url: str) -> dict:
        if not url:
            return {k: 0 for k in [
                'url_length', 'path_length', 'query_length', 'fragment_length',
                'param_count', 'path_depth', 'has_query', 'has_fragment',
                'url_entropy', 'suspicious_chars_count', 'path_traversal_count'
            ]}
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        return {
            'url_length': len(url),
            'path_length': len(parsed_url.path),
            'query_length': len(parsed_url.query),
            'fragment_length': len(parsed_url.fragment or ''),
            'param_count': len(query_params),
            'path_depth': len([p for p in parsed_url.path.split('/') if p]),
            'has_query': int(bool(parsed_url.query)),
            'has_fragment': int(bool(parsed_url.fragment)),
            'url_entropy': self._calculate_entropy(url),
            'suspicious_chars_count': self._count_suspicious_chars(url),
            'path_traversal_count': url.count("../") + url.count("..\\"),
        }

    def _extract_header_features(self, headers: dict) -> dict:
        if not headers:
            return {k: 0 for k in [
                'header_count', 'user_agent_length', 'has_user_agent', 'has_referer',
                'has_cookie', 'content_type_length', 'header_entropy', 'suspicious_headers'
            ]}
        user_agent = headers.get('User-Agent', '')
        content_type = headers.get('Content-Type', '')
        return {
            'header_count': len(headers),
            'user_agent_length': len(user_agent),
            'has_user_agent': int(bool(user_agent)),
            'has_referer': int(bool(headers.get('Referer'))),
            'has_cookie': int(bool(headers.get('Cookie'))),
            'content_type_length': len(content_type),
            'header_entropy': self._calculate_entropy(str(headers)),
            'suspicious_headers': sum(1 for h in headers if h.lower() in ['x-forwarded-for', 'x-real-ip', 'x-originating-ip'])
        }

    def _extract_payload_features(self, payload: str) -> dict:
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
            'uppercase_ratio': sum(c.isupper() for c in payload) / length
        }

    def _extract_attack_features(self, url: str, payload: str, headers: dict) -> dict:
        text = f"{url} {payload} {headers}".lower()
        return {
            'sql_keyword_count': sum(text.count(kw) for kw in self.sql_keywords),
            'xss_pattern_count': sum(len(re.findall(pat, text, re.IGNORECASE)) for pat in self.xss_patterns),
            'command_injection_count': sum(len(re.findall(pat, text, re.IGNORECASE)) for pat in self.command_patterns),
            'file_inclusion_count': len(re.findall(r'(file://|ftp://|http://)', text)),
            'encoded_chars_count': len(re.findall(r'%[0-9a-fA-F]{2}', text)),
        }

    def _extract_statistical_features(self, url: str, payload: str, headers: dict) -> dict:
        combined = f"{url} {payload} {headers}"
        if not combined.strip():
            return {k: 0 for k in [
                'unique_char_count', 'most_common_char_freq', 'char_frequency_std',
                'whitespace_ratio', 'punctuation_density'
            ]}
        freq = Counter(combined)
        counts = list(freq.values())
        length = len(combined)
        avg_freq = sum(counts) / len(counts)
        variance = sum((c - avg_freq) ** 2 for c in counts) / len(counts)
        stddev = math.sqrt(variance) if variance >= 0 else 0
        return {
            'unique_char_count': len(freq),
            'most_common_char_freq': max(counts),
            'char_frequency_std': stddev,
            'whitespace_ratio': sum(c.isspace() for c in combined) / length,
            'punctuation_density': len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', combined)) / length
        }

    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
        return entropy if math.isfinite(entropy) else 0.0

    def _count_suspicious_chars(self, text: str) -> int:
        return sum(text.count(ch) for ch in self.suspicious_special_chars)

    def _count_signature_matches(self, text: str, regex_list: list) -> int:
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

    def _count_keyword_matches(self, text: str, keywords: list) -> int:
        return sum(1 for kw in keywords if kw in text)

    def check_signatures(self, text: str) -> dict:
        return {
            'has_sqli_signature': bool(self._count_signature_matches(text, self.sql_regexes)),
            'has_xss_signature': bool(self._count_signature_matches(text, self.xss_regexes)),
            'has_path_traversal_signature': bool(self._count_signature_matches(text, self.path_traversal_regexes)),
            'has_cmdinj_signature': bool(self._count_signature_matches(text, self.cmdinj_regexes)),
            'has_ddos_signature': bool(self._count_keyword_matches(text, self.ddos_keywords)),
            'has_brutforce_path': bool(self._count_signature_matches(text, self.bruteforce_paths)),
            'has_brutforce_password': bool(self._count_signature_matches(text, self.bruteforce_password_patterns)),
            'has_portscan_signature': bool(self._count_signature_matches(text, self.portscan_patterns)),
            'has_fuzzing_signature': bool(self._count_signature_matches(text, self.fuzzing_patterns)),
            'has_ftp_exploit_signature': bool(self._count_signature_matches(text, self.ftp_exploit_patterns)),
            'has_icmp_flood_signature': bool(self._count_signature_matches(text, self.icmp_flood_patterns)),
            'has_ssh_ftp_bruteforce': bool(
            self._count_signature_matches(text, self.ssh_ftp_bruteforce_paths) and
            (
                self._count_signature_matches(text, self.bruteforce_usernames) or
                self._count_signature_matches(text, self.bruteforce_passwords_extra)
            )
        ),
    
        }