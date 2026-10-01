import os
import subprocess
from backend.twin.real_analyzer import analyze_real_repository
from backend.twin.schema import TwinNodeSchema, TwinEdgeSchema
from backend.regression.selector import RegressionSelector
from backend.contracts.models import SecurityContract
from backend.regression.git_adapter import RealGitAdapter

def main():
    repo_path = os.path.abspath("target")
    data = analyze_real_repository(repo_path)
    
    # 1. Build TwinNodeSchemas from the raw data
    nodes = []
    
    for r in data["routes"]:
        source_path = r["source"].split(":")[0]
        nodes.append(TwinNodeSchema(id=r["path"], node_type="interface", name=f"{r['method']} {r['path']}", source_ref=r["source"], commit_sha="HEAD", properties={}))
        nodes.append(TwinNodeSchema(id=f"mod_{source_path}", node_type="module", name=source_path, source_ref=source_path, commit_sha="HEAD", properties={}))
        
    for i in data["imports"]:
        nodes.append(TwinNodeSchema(id=f"mod_{i['to']}", node_type="module", name=i["to"], source_ref=i["to"], commit_sha="HEAD", properties={}))

    edges = []
    for i in data["imports"]:
        # source_id is the module ID of the from_file
        from_file = i["from"]
        to_file = i["to"]
        edges.append(TwinEdgeSchema(id=f"edge_{from_file}_{to_file}", source_id=f"mod_{from_file}", target_id=f"mod_{to_file}", relationship_type="IMPORTS"))

    # 2. Build Contracts
    contracts = []
    for r in data["routes"]:
        contracts.append(SecurityContract(resource=f"{r['method']} {r['path']}", source_ref=r["source"], coverage_tier="Tier 1", rules=[]))
        
    selector = RegressionSelector(twin_nodes=nodes, twin_edges=edges, contracts=contracts)
    
    print("=== TASK 6a: Real import-graph test ===")
    print("Simulating change to api/_session.js...")
    diff_a = [{"status": "M", "a_path": "api/_session.js", "b_path": "api/_session.js", "changed_lines": [1]}]
    res_a = selector.select_tests(diff_a)
    print(f"Total routes selected: {len(res_a['selected_tests'])}")
    print("Examples:")
    for t in res_a["selected_tests"][:3]:
        print(f" - {t['contract_resource']} (Reason: {t['reason']})")
        
    print("\n=== TASK 6c: Real diff on the pinned repo ===")
    
    print("Diff 1: Touching only a non-security file (CSS)")
    diff_css = [{"status": "M", "a_path": "public/style.css", "b_path": "public/style.css", "changed_lines": [1]}]
    res_css = selector.select_tests(diff_css)
    print(f"Total tests selected: {len(res_css['selected_tests'])}")
    print("Examples of skipped:")
    for t in res_css["skipped_tests"][:3]:
        print(f" - {t['contract_resource']} (Reason: {t['reason']})")
        
    print("\nDiff 2: Touching a mapped API file (api/health.js)")
    diff_api = [{"status": "M", "a_path": "api/health.js", "b_path": "api/health.js", "changed_lines": [1]}]
    res_api = selector.select_tests(diff_api)
    print(f"Total routes selected: {len(res_api['selected_tests'])}")
    print("Examples:")
    for t in res_api["selected_tests"][:3]:
        print(f" - {t['contract_resource']} (Reason: {t['reason']})")
        
if __name__ == "__main__":
    main()
