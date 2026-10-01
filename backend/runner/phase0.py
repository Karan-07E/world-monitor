import os
import json
from pathlib import Path
from backend.runner.capture import capture_environment
from backend.runner.guard import enforce_target_guard
from backend.twin.client_scope import analyze_client_scope
from backend.twin.analyzer import map_repository
from backend.runner.docker_gen import identify_required_services, check_dockerfile

def run_phase0(repo_root: str, target_url: str):
    """
    Executes Phase 0: Repository Mapping.
    """
    print(f"Starting Phase 0 against target: {target_url}")
    
    # 1. Guard check
    try:
        pinned_url = enforce_target_guard(target_url)
        print(f"[OK] Target URL passed guard. Pinned URL: {pinned_url}")
    except ValueError as e:
        print(f"[FAIL] Target guard rejected URL: {e}")
        return False
        
    # 2. Capture Environment (commit, runtime, lockfiles)
    print("Capturing environment...")
    env_data = capture_environment(repo_root)
    
    # 3. Analyze client scope (Tauri, PWA, Web)
    print("Analyzing client scope...")
    scope_data = analyze_client_scope(repo_root)
    
    # 4. Map repository (auth, roles)
    print("Mapping repository for Auth and Roles...")
    twin_data = map_repository(repo_root)
    
    # Check if horizontal/vertical tests are applicable
    auth_info = twin_data.get("auth", {})
    if auth_info.get("horizontal_tests") == "NOT APPLICABLE":
        print(f"[WARNING] Authorization tests NOT APPLICABLE. Reason: {auth_info.get('reason')}")
        print("[WARNING] Informing before Phase 2.")
        
    # 5. Check services
    print("Checking required services and Dockerfile...")
    has_dockerfile = check_dockerfile(repo_root)
    services = identify_required_services(repo_root)
    
    # 6. Output recon.json
    recon = {
        "target_url": pinned_url,
        "environment": env_data,
        "scope": scope_data,
        "twin": twin_data,
        "services": services,
        "has_dockerfile": has_dockerfile
    }
    
    recon_path = Path("recon.json")
    with open(recon_path, "w") as f:
        json.dump(recon, f, indent=2)
        
    print(f"[OK] Phase 0 complete. Output written to {recon_path.absolute()}")
    return True

if __name__ == "__main__":
    target = os.getenv("TARGET_URL", "http://localhost:3000")
    run_phase0("target", target)
