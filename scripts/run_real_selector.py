import os
import json
from backend.twin.real_analyzer import analyze_real_repository
from backend.twin.builder import export_twin_to_json, populate_twin_from_recon
from backend.regression.selector import RegressionSelector
from backend.contracts.models import SecurityContract
from backend.db.base import Base
from backend.db.session import engine, SessionLocal
from backend.twin.schema import TwinNodeSchema

def run():
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../target'))
    
    twin_data = analyze_real_repository(repo_path)
    recon = {
        "environment": {"commit_sha": "actual_pinned_commit_sha"},
        "twin": twin_data
    }
    
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    populate_twin_from_recon(recon, session)
    export = export_twin_to_json(session)
    
    nodes = [TwinNodeSchema(**n) for n in export["nodes"]]
    contracts = []
    
    for r in twin_data["routes"]:
        source_ref = r["source"]
        contracts.append(SecurityContract(
            resource=f"{r['method']} {r['path']}",
            source_ref=source_ref,
            coverage_tier="Tier 1",
            rules=[]
        ))

    selector = RegressionSelector(twin_nodes=nodes, contracts=contracts)

    print("=== SCENARIO 1: Synthetic Diff on a Real API Route ===")
    print("Diff touches: api/oauth-protected-resource.ts (and its logic)")
    synthetic_diff = [{
        "status": "M",
        "a_path": "api/oauth-protected-resource.ts",
        "b_path": "api/oauth-protected-resource.ts",
        "changed_lines": [59]
    }]
    
    res = selector.select_tests(synthetic_diff)
    print(f"Selected Tests: {len(res['selected_tests'])}")
    for t in res["selected_tests"]:
        print(f" -> Selected: {t['contract_resource']} ({t['reason']})")
        
    print(f"Skipped Tests: {len(res['skipped_tests'])}")
    
    session.close()

if __name__ == "__main__":
    run()
