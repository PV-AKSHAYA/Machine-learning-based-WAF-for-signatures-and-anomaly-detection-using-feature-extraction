import csv
import random
import json

def gen_domains(num=200):
    tlds = ['com', 'net', 'org', 'io', 'biz', 'info', 'co', 'us', 'uk', 'edu']
    prefixes = ['example', 'testsite', 'myapp', 'webportal', 'services', 'secure', 'shop', 'shoponline', 'api', 'loginpage']
    domains = []
    for _ in range(num):
        prefix = random.choice(prefixes)
        tld = random.choice(tlds)
        domains.append(f"{prefix}{random.randint(1,999)}.{tld}")
    return domains

def csv_write(filename, rows):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['method','url','payload','headers','is_malicious'])
        w.writerows(rows)
    print(f"Generated {len(rows)} rows in {filename}")

def make_sample(method, url_format, payload, headers, malicious=0):
    # headers is a dict, we convert it to JSON string here as expected by feature extractor
    headers_json = json.dumps(headers) if isinstance(headers, dict) else headers
    return [method, url_format, payload, headers_json, malicious]

def generate_samples(category, domains, count=100):
    samples = []
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
        'curl/7.64.1', 'PostmanRuntime/7.26.8', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Mozilla/5.0 (Linux; Android 10; SM-G970F Build/QP1A.190711.020)'
    ]

    for _ in range(count):
        domain = random.choice(domains)
        if category == 'benign':
            # Benign random normal browsing with realistic headers
            urls = [
                f"http://{domain}/",
                f"https://{domain}/about",
                f"http://{domain}/help?q=faq",
                f"http://{domain}/products?id={random.randint(1, 500)}",
                f"https://{domain}/blog/post/{random.randint(100,999)}",
                f"http://{domain}/contact",
            ]
            url = random.choice(urls)
            method = random.choice(['GET','POST'])
            payload = ''
            if method == 'POST' and 'login' in url:
                payload = "username=validuser&password=goodpass"
            elif method == 'POST':
                payload = "data=normaldata"

            headers = {
                'User-Agent': random.choice(user_agents),
                'Referer': f"http://{random.choice(domains)}/",
                'Cookie': f'sessionid={random.randint(1000,9999)}; userid={random.randint(100,999)}'
            }

            samples.append(make_sample(method, url, payload, headers, malicious=0))

        elif category == 'xss':
            xss_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert(1337)>",
                "%3Ciframe%20src%3Djavascript:alert(2)%3E",
                "<body onload=alert(1)>",
            ]
            method = random.choice(['GET','POST'])
            xss_pl = random.choice(xss_payloads)
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            if method == 'GET':
                url = f"http://{domain}/search?q={xss_pl}"
                payload = ''
            else:
                url = f"http://{domain}/submit"
                payload = f"comment={xss_pl}"
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'sqli':
            sqli_payloads = [
                "1' OR 1=1--",
                "admin' --",
                "'; DROP TABLE users--",
                "2 UNION SELECT username, password FROM users--",
                "1 AND SLEEP(5)--"
            ]
            method = random.choice(['GET', 'POST'])
            sqli_pl = random.choice(sqli_payloads)
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            if method == 'GET':
                url = f"http://{domain}/product?id={sqli_pl}"
                payload = ''
            else:
                url = f"http://{domain}/auth"
                payload = f"username={sqli_pl}&password=any"
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'portscanning':
            ports = [22, 80, 443, 8080, 3306, 21, 25]
            tools = ['nmap', 'masscan', 'scan', 'portscan']
            port = random.choice(ports)
            tool = random.choice(tools)
            method = 'GET'
            url = f"http://{domain}/scan?target=192.168.1.{random.randint(1,254)}:{port}&tool={tool}"
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, '', headers, malicious=1))

        elif category == 'dos':
            method = random.choice(['GET', 'POST'])
            url = f"http://{domain}/?type=dos&flood=1"
            payload = "ping=" + str(random.randint(1000,10000000)) if method == 'POST' else ''
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'dos_slowloris':
            method = random.choice(['GET', 'POST'])
            url = f"http://{domain}/?type=slowloris&attack=active"
            payload = "slowloris=on" if method == 'POST' else ''
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'dos_hulk':
            method = random.choice(['GET', 'POST'])
            url = f"http://{domain}/?type=hulk&attack=run"
            payload = "hulk=attack" if method == 'POST' else ''
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'ddos':
            method = random.choice(['GET', 'POST'])
            url = f"http://{domain}/?type=ddos&layer=7"
            payload = "flood=ddos" if method == 'POST' else ''
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'bruteforce':
            common_users = ['admin','root','user','guest','test']
            common_passwords = ['123456','password','admin','letmein','1234']
            user = random.choice(common_users)
            pwd = random.choice(common_passwords)
            method = 'POST'
            url = f"http://{domain}/login"
            payload = f"username={user}&password={pwd}"
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'bruteforce_webattack':
            users = ['administrator','test','user123','adminuser']
            pwds = ['password1','passw0rd','qwerty123','letmein123']
            user = random.choice(users)
            pwd = random.choice(pwds)
            method = 'POST'
            url = f"http://{domain}/auth"
            payload = f"user={user}&pass={pwd}"
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'fuzzing':
            fuzz_payloads = ['FUZZ', 'AAAA'*8, "';!--\"<XSS>=&{()}","%00%ff%00","%27%22%3C%3E%26%25%23%40"]
            method = random.choice(['GET','POST'])
            fuzz = random.choice(fuzz_payloads)
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            if method == 'GET':
                url = f"http://{domain}/search?q={fuzz}"
                payload = ''
            else:
                url = f"http://{domain}/data"
                payload = f"payload={fuzz}"
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'webattack_xss':
            methods = ['GET','POST']
            xss_payloads = [
                "%3Ciframe%20onload=alert(3)%3E",
                "<img src=x onerror=alert(7)>",
                "%3Csvg%2Fonload%3Dalert(8)%3E",
                "%3Cmarquee%20onstart=alert(5)%3E",
                "<embed src=javascript:alert(9)>"
            ]
            method = random.choice(methods)
            xss_pl = random.choice(xss_payloads)
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            if method == 'GET':
                url = f"http://{domain}/comment?c={xss_pl}"
                payload = ''
            else:
                url = f"http://{domain}/feedback"
                payload = f"msg={xss_pl}"
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'exploiting_ftp':
            method = random.choice(['GET','POST'])
            urls = [
                f"ftp://{domain}/",
                f"http://{domain}/?ftp=1",
                f"http://malicious{random.randint(1,1000)}.com/ftp?exploit=1"
            ]
            url = random.choice(urls)
            payload = "command=open ftp://bad.com" if method == 'POST' else ''
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'ftp_bruteforce':
            users = ['ftpuser','ftpadmin','anonymous','user']
            pwds = ['123456','password','letmein','guest']
            user = random.choice(users)
            pwd = random.choice(pwds)
            method = 'POST'
            url = f"http://{domain}/ftp-login"
            payload = f"user={user}&pass={pwd}"
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'ssh_bruteforce':
            users = ['root','admin','test','git','ubuntu']
            pwds = ['1234','password','test','gitpass','ubuntu']
            user = random.choice(users)
            pwd = random.choice(pwds)
            method = 'POST'
            url = f"http://{domain}/ssh-login"
            payload = f"user={user}&pass={pwd}"
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

        elif category == 'icmp_flood':
            method = random.choice(['GET','POST'])
            url = f"http://{domain}/"
            payload = "icmp_flood=1" if method == 'POST' else ''
            headers = {
                'User-Agent': random.choice(user_agents)
            }
            samples.append(make_sample(method, url, payload, headers, malicious=1))

    return samples

def main():
    categories_malicious = [
        'xss', 'sqli', 'portscanning', 'dos', 'dos_slowloris', 'dos_hulk', 'ddos',
        'bruteforce', 'bruteforce_webattack', 'fuzzing', 'webattack_xss', 'exploiting_ftp',
        'ftp_bruteforce', 'ssh_bruteforce', 'icmp_flood'
    ]
    benign_count = 450
    malicious_count_per_cat = 500 // len(categories_malicious)  # about 33 each

    all_rows = []
    domains = gen_domains(200)  # Keep domains varied

    print(f"Generating {benign_count} benign samples...")
    benign_samples = generate_samples('benign', domains, count=benign_count)
    all_rows.extend(benign_samples)

    for cat in categories_malicious:
        print(f"Generating {malicious_count_per_cat} samples for malicious category: {cat} ...")
        samples = generate_samples(cat, domains, count=malicious_count_per_cat)
        all_rows.extend(samples)

    csv_write("waf_test_dataset_balanced.csv", all_rows)

if __name__ == "__main__":
    main()
