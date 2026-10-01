import os
import json
from pathlib import Path
from typing import Dict, Any

def analyze_client_scope(repo_root: str) -> Dict[str, Any]:
    """
    Analyzes the repository to determine the client delivery model:
    - Web (Responsive web app)
    - PWA / Service Workers
    - Tauri (Desktop shell)
    """
    repo_path = Path(repo_root)
    scope = {
        "web": True,  # Assume web by default for TS projects of this type
        "pwa": False,
        "tauri": False,
        "tauri_details": {}
    }

    # Check for PWA/Service Worker
    if list(repo_path.rglob("service-worker.ts")) or list(repo_path.rglob("sw.js")) or list(repo_path.rglob("manifest.json")):
        scope["pwa"] = True

    # Check for Tauri
    tauri_conf_paths = list(repo_path.rglob("tauri.conf.json"))
    if tauri_conf_paths:
        scope["tauri"] = True
        try:
            with open(tauri_conf_paths[0], 'r') as f:
                tauri_conf = json.load(f)
                
                # Extract Tauri specific security scope details
                tauri_details = {}
                
                # Check remote content (allowlist / CSP in Tauri)
                tauri_details["allowlist"] = tauri_conf.get("tauri", {}).get("allowlist", {})
                tauri_details["capabilities"] = "Needs capabilities check (Tauri v2 uses capabilities directory/config)"
                
                # Look for remote URL loading in windows
                windows = tauri_conf.get("tauri", {}).get("windows", [])
                tauri_details["loads_remote_content"] = any(
                    w.get("url", "").startswith("http") and not w.get("url", "").startswith("http://localhost") 
                    for w in windows
                )
                
                scope["tauri_details"] = tauri_details
        except Exception as e:
            scope["tauri_details"] = {"error": str(e)}

    return scope
