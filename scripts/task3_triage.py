import os
import json
import urllib.request
import time
from backend.twin.real_analyzer import analyze_real_repository

TARGET_URL = "http://localhost:3000"

def get_no_control_routes():
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../target'))
    twin_data = analyze_real_repository(repo_path)
    
    no_control_routes = []
    for route in twin_data["routes"]:
        # Based on how real_analyzer sets edges: 'auth' flag means protected.
        if not route.get("auth", False):
            no_control_routes.append((route["method"], route["path"]))
    return no_control_routes

def triage_route(method, path):
    url = TARGET_URL + path
    if method not in ["GET", "HEAD", "OPTIONS"]:
        return "ERROR", "N/A", "0", "REQUIRES_PARAMS", "Method not allowed by R4"
        
    # Replace dynamic params like :id or [...path]
    safe_path = path.replace(":", "test_").replace("[", "").replace("]", "").replace("...", "test_")
    url = TARGET_URL + safe_path
    
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as res:
            status = res.status
            ctype = res.info().get("Content-Type", "N/A")
            body = res.read()
            size = len(body)
            # Classification
            classif = "PUBLIC_DATA"
            if ctype.startswith("text/html"):
                reason = "Dev server SPA fallback or public page"
            else:
                reason = "Public data endpoint"
            return status, ctype, size, classif, reason
    except urllib.error.HTTPError as e:
        status = e.code
        ctype = e.headers.get("Content-Type", "N/A")
        size = len(e.read())
        classif = "ERROR" if status >= 500 else "REQUIRES_PARAMS"
        return status, ctype, size, classif, e.reason
    except Exception as e:
        return "ERROR", "N/A", "0", "ERROR", str(e)

def main():
    print("=== TASK 3 - TRIAGE ROUTES FLAGGED NO_CONTROL_FOUND ===")
    routes = get_no_control_routes()
    print(f"Found {len(routes)} routes with NO_CONTROL_FOUND.")
    
    # Cap to 96 or actual
    routes = routes[:96]
    
    print("ROUTE | METHOD | STATUS | CONTENT-TYPE | SIZE | CLASSIFICATION | REASON")
    print("-" * 100)
    
    candidates = []
    count = 0
    
    for method, path in routes:
        count += 1
        if count % 5 == 0:
            time.sleep(1) # Cap 5 req/s
            
        status, ctype, size, classif, reason = triage_route(method, path)
        print(f"{path} | {method} | {status} | {ctype} | {size} | {classif} | {reason}")
        
        if classif in ["USER_OR_PRIVATE_DATA", "INTERNAL_OR_ADMIN"] and status == 200:
            candidates.append((method, path))
            
    print("-" * 100)
    print(f"Candidates found for further review: {len(candidates)}")
    for c in candidates:
        print(c)

if __name__ == "__main__":
    main()
