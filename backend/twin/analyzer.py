import os
import subprocess
import json
from pathlib import Path
from typing import Dict, Any

def run_semgrep_analysis(repo_root: str) -> Dict[str, Any]:
    """
    Runs Semgrep rules to enumerate routes, API handlers, and auth checks.
    (Stubbed for the purpose of the initial Phase 0 setup).
    """
    # In a real environment, we'd run:
    # subprocess.check_output(["semgrep", "scan", "--json", "--config", "rules/", repo_root])
    return {
        "routes": [],
        "auth_methods": ["session_cookie"], # Mocked discovery
        "roles_found": False
    }

def analyze_roles_and_auth(repo_root: str) -> Dict[str, Any]:
    """
    Determines if user-scoped resources and roles (like Admin, User) exist.
    """
    repo_path = Path(repo_root)
    # Simple heuristic to look for "role", "admin", "RBAC" in the codebase
    # Real implementation uses Tree-Sitter and Semgrep
    
    roles_found = False
    
    # Quick scan of server/api directories for role indicators
    check_dirs = [repo_path / "server", repo_path / "api", repo_path / "src"]
    for d in check_dirs:
        if not d.exists():
            continue
        for ext in ["*.ts", "*.js", "*.tsx", "*.jsx"]:
            for filepath in d.rglob(ext):
                try:
                    content = filepath.read_text(encoding="utf-8").lower()
                    if "role" in content or "isadmin" in content or "permission" in content:
                        roles_found = True
                        break
                except Exception:
                    pass
        if roles_found:
            break
            
    return {
        "roles_exist": roles_found,
        "auth_mechanism": "detected_from_semgrep",
        "vertical_tests": "APPLICABLE" if roles_found else "NOT APPLICABLE",
        "horizontal_tests": "APPLICABLE" if roles_found else "NOT APPLICABLE",
        "reason": "Roles/Permissions concepts found in source code." if roles_found else "No role or permission concepts found in the codebase."
    }

def map_repository(repo_root: str) -> Dict[str, Any]:
    """Main entrypoint for Phase 0 twin analysis."""
    auth_data = analyze_roles_and_auth(repo_root)
    return {
        "auth": auth_data,
        "routes": []
    }
