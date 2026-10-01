import urllib.request
import json
import os
import subprocess

TARGET_URL = "http://localhost:3000"
ROUTES_TO_TEST = ["/api/health", "/api/download", "/api/live"]

def fetch_headers(url, headers=None):
    if headers is None: headers = {}
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return dict(res.info()), res.status, res.reason
    except urllib.error.HTTPError as e:
        return dict(e.headers), e.code, e.reason
    except Exception as e:
        return None, None, str(e)

def parse_vercel_json():
    with open("target/vercel.json", "r") as f:
        data = json.load(f)
    # find global headers (source: "/(.*)")
    for h in data.get("headers", []):
        if h.get("source") == "/(.*)":
            return {k["key"].lower(): k["value"] for k in h.get("headers", [])}
    return {}

def main():
    print("=== TASK 2 - REAL BASELINE ON THE RUNNING TARGET ===")
    
    # 1. Security Headers (CSP, XFO, XCTO, RP, PP, HSTS)
    print("\n--- Security Headers ---")
    headers, status, reason = fetch_headers(TARGET_URL + "/")
    vercel_headers = parse_vercel_json()
    
    for header in ["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "strict-transport-security"]:
        dev_val = headers.get(header) if headers else None
        prod_val = vercel_headers.get(header)
        
        if header == "strict-transport-security":
            print(f"Check: {header.upper()}\nURL: {TARGET_URL}/\nResult: NOT APPLICABLE (Plain HTTP)\nLabel: DEV-SERVER")
        else:
            if dev_val == prod_val:
                print(f"Check: {header.upper()}\nURL: {TARGET_URL}/\nEvidence: {dev_val}\nResult: PASS\nLabel: DEV-SERVER (matches CONFIG-STATIC)")
            elif prod_val and not dev_val:
                print(f"Check: {header.upper()}\nURL: {TARGET_URL}/\nEvidence: Dev: None | Prod: {prod_val[:50]}...\nResult: PASS\nLabel: CONFIG-STATIC (Missing on dev, present in config)")
            else:
                print(f"Check: {header.upper()}\nURL: {TARGET_URL}/\nEvidence: Dev: {dev_val} | Prod: {prod_val}\nResult: FAIL\nLabel: DEV-SERVER")
        print("-")

    # 2. CORS Checks
    print("\n--- CORS Checks ---")
    for route in ROUTES_TO_TEST:
        for origin in ["https://evil.example", "null"]:
            h, s, r = fetch_headers(TARGET_URL + route, {"Origin": origin})
            if h is None:
                print(f"Check: CORS ({origin})\nURL: {TARGET_URL + route}\nResult: ERROR ({r})\nLabel: DEV-SERVER\n-")
                continue
            acao = h.get("access-control-allow-origin")
            acac = h.get("access-control-allow-credentials")
            if acao == origin or acao == "*":
                print(f"Check: CORS ({origin})\nURL: {TARGET_URL + route}\nEvidence: ACAO={acao}, ACAC={acac}\nResult: FAIL (Reflected Origin)\nLabel: DEV-SERVER")
            else:
                print(f"Check: CORS ({origin})\nURL: {TARGET_URL + route}\nEvidence: ACAO={acao}\nResult: PASS\nLabel: DEV-SERVER")
            print("-")
            
    # 3. Cookie Flags
    print("\n--- Cookie Flags ---")
    h, s, r = fetch_headers(TARGET_URL + "/api/auth/session")
    if h is None:
        print(f"Check: Cookie Flags\nURL: {TARGET_URL}/api/auth/session\nResult: ERROR ({r})\nLabel: DEV-SERVER")
    else:
        set_cookie = h.get("set-cookie")
        if not set_cookie:
            print(f"Check: Cookie Flags\nURL: {TARGET_URL}/api/auth/session\nEvidence: no cookies set\nResult: PASS\nLabel: DEV-SERVER")
        else:
            print(f"Check: Cookie Flags\nURL: {TARGET_URL}/api/auth/session\nEvidence: {set_cookie}\nResult: {'FAIL' if 'Secure' not in set_cookie else 'PASS'}\nLabel: DEV-SERVER")

    # 4. Dependency Audit
    print("\n--- Dependency Audit ---")
    try:
        # Run npm audit --json in target
        res = subprocess.run(["npm", "audit", "--json"], cwd="target", capture_output=True, text=True)
        audit_json = json.loads(res.stdout)
        vuln_count = audit_json.get("metadata", {}).get("vulnerabilities", {}).get("total", 0)
        exit_code = res.returncode
        print(f"Command: npm audit --json\nExit Code: {exit_code}\nEvidence: {vuln_count} vulnerabilities found\nResult: {'FAIL' if vuln_count > 0 else 'PASS'}\nLabel: DEV-SERVER")
    except Exception as e:
        print(f"Command: npm audit --json\nExit Code: N/A\nEvidence: {str(e)}\nResult: ERROR\nLabel: DEV-SERVER")

if __name__ == "__main__":
    main()
