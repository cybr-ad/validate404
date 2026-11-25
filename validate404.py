
import requests
import re
import hashlib
import secrets
from urllib.parse import urlparse

s = requests.Session()
s.headers["User-Agent"] = "404-Validator/1.0"

def fingerprint(r):
    body = re.sub(rb'\s+', b' ', r.content).strip()
    return (
        r.status_code,
        hashlib.sha256(body).hexdigest()
    )

def main():
    base = input("Target URL: ").strip().rstrip("/")
    filename = input("Gobuster output file: ").strip()

    try:
        with open(filename) as f:
            lines = f.readlines()
    except OSError as e:
        print("File error:", e)
        return

    origin = urlparse(base)
    urls = []

    for line in lines:
        match = re.search(r'^\s*(\S+)\s+\(Status:\s*404\)', line)

        if match:
            path = match.group(1)
            urls.append(base + "/" + path.lstrip("/"))

    print(f"\n[*] Found {len(urls)} 404 entries")

    baselines = []

    print("[*] Generating random 404 baselines")

    for _ in range(7):
        random_path = secrets.token_hex(16)

        try:
            r = s.get(
                base + "/" + random_path,
                timeout=10,
                allow_redirects=True
            )
            baselines.append(fingerprint(r))
        except requests.RequestException:
            pass

    if len(baselines) < 5:
        print("[!] Baseline unavailable or unstable")
        return

    from collections import Counter
    common, count = Counter(baselines).most_common(1)[0]

    if count < 5:
        print("[!] Inconsistent baseline. Results need manual review.")

    with open("404-validation.txt", "w") as out:

        for url in dict.fromkeys(urls):

            if urlparse(url).netloc != origin.netloc:
                continue

            try:
                r = s.get(
                    url,
                    timeout=10,
                    allow_redirects=True
                )

                fp = fingerprint(r)

                if fp == common:
                    status = "LIKELY_FALSE_POSITIVE"
                else:
                    status = "REVIEW"

                result = (
                    f"{status} | HTTP {r.status_code} | "
                    f"{len(r.content)} bytes | {url}"
                )

                print(result)
                out.write(result + "\n")

            except requests.RequestException as e:
                print("[ERROR]", url, e)

    print("\n[*] Saved to 404-validation.txt")


if __name__ == "__main__":
    main()

