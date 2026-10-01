import os
import json
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

def hash_file(filepath: Path) -> str:
    """Returns SHA256 hash of a file, or empty string if not found."""
    if not filepath.exists():
        return ""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def capture_lockfile_hashes(repo_root: Path) -> Dict[str, str]:
    """Hashes lockfiles across root, cli/, and sdk/."""
    lockfiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "poetry.lock"]
    directories = ["", "cli", "sdk"]
    hashes = {}
    
    for d in directories:
        dir_path = repo_root / d
        if not dir_path.exists():
            continue
            
        for lf in lockfiles:
            file_path = dir_path / lf
            if file_path.exists():
                rel_path = str(file_path.relative_to(repo_root))
                hashes[rel_path] = hash_file(file_path)
                
    return hashes

def capture_runtime_info() -> Dict[str, str]:
    """Captures runtime versions (Python, Node)."""
    versions = {}
    try:
        versions["python"] = subprocess.check_output(["python", "--version"], text=True).strip()
    except Exception:
        versions["python"] = "unknown"
        
    try:
        versions["node"] = subprocess.check_output(["node", "--version"], text=True).strip()
    except Exception:
        versions["node"] = "unknown"
        
    return versions

def capture_environment(repo_root: str) -> Dict[str, Any]:
    """
    Captures pinned commit, timestamp, runtime versions, and lockfile hashes.
    """
    repo_path = Path(repo_root)
    
    try:
        # Get commit SHA and branch
        commit_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root, text=True).strip()
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root, text=True).strip()
    except Exception as e:
        commit_sha = "unknown"
        branch = "unknown"

    data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "commit_sha": commit_sha,
        "branch": branch,
        "runtimes": capture_runtime_info(),
        "lockfile_hashes": capture_lockfile_hashes(repo_path)
    }
    
    return data

if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(capture_environment(root), indent=2))
