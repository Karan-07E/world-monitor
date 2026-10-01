import pytest
from backend.engines.checks import run_all_baseline_engines
from backend.engines.models import EngineResult

def test_run_all_baseline_engines():
    target_url = "http://localhost:8080"
    repo_root = "/target"
    scope = {"web": True, "tauri": False}
    
    results = run_all_baseline_engines(target_url, repo_root, scope)
    
    # We have 9 engines (7 areas + availability + dependency)
    assert len(results) == 9
    
    for res in results:
        assert isinstance(res, EngineResult)
        assert res.area in [
            "Auth", "Authorization", "Input/Data", "API", 
            "Client", "Transport", "Privacy", 
            "Availability-Safe", "Dependency"
        ]
        assert res.status in ["PASS", "FAIL", "NOT APPLICABLE", "ERROR"]
        
def test_client_engine_scope():
    from backend.engines.checks import ClientEngine
    
    # When web scope is true
    res = ClientEngine().check_csp("http://loc", {"web": True})
    assert res.status != "NOT APPLICABLE"
    
    # When web scope is false (e.g., native only)
    res = ClientEngine().check_csp("http://loc", {"web": False})
    assert res.status == "NOT APPLICABLE"
    assert res.reason == "Web scope not detected"
