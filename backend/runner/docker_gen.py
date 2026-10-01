import os
from pathlib import Path
from typing import List, Dict

def identify_required_services(repo_root: str) -> Dict[str, List[str]]:
    """
    Reads .env.example to find required services (e.g., Redis, DB, API keys).
    """
    env_example = Path(repo_root) / ".env.example"
    services = {
        "databases": [],
        "caches": [],
        "external_apis": [],
        "other": []
    }
    
    if not env_example.exists():
        return services
        
    with open(env_example, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            key = line.split("=")[0]
            
            if "REDIS" in key or "CACHE" in key:
                services["caches"].append(key)
            elif "DB" in key or "POSTGRES" in key or "DATABASE" in key or "MONGO" in key:
                services["databases"].append(key)
            elif "API_KEY" in key or "TOKEN" in key or "SECRET" in key:
                services["external_apis"].append(key)
            else:
                # Add heuristically some other common service keys
                if "URL" in key or "URI" in key or "HOST" in key:
                    services["other"].append(key)
                    
    return services

def check_dockerfile(repo_root: str) -> bool:
    """Checks if a Dockerfile exists."""
    return (Path(repo_root) / "Dockerfile").exists()

