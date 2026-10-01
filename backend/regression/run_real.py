import os
from backend.regression.git_adapter import GitAdapter
from backend.regression.selector import RegressionSelector
from backend.twin.schema import TwinNodeSchema, NodeType
from backend.contracts.models import SecurityContract, AuthenticationContract

def run_real_git_test():
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../target'))
    adapter = GitAdapter(repo_path)
    
    # Try diffing HEAD~1 to HEAD
    try:
        diff = adapter.get_diff("HEAD~1", "HEAD")
        print(f"Found {len(diff)} changed files between HEAD~1 and HEAD.")
    except Exception as e:
        print(f"Error getting diff: {e}")
        return

    # Let's map real files based on what's in the repo
    # Assuming there's a package.json and maybe some ts files
    nodes = [
        TwinNodeSchema(
            id="node_1", node_type=NodeType.INTERFACE, name="Index HTML",
            source_ref="index.html:1", commit_sha="abc", properties={}
        ),
        TwinNodeSchema(
            id="node_2", node_type=NodeType.INTERFACE, name="Vite Config",
            source_ref="vite.config.ts:1", commit_sha="abc", properties={}
        )
    ]
    contracts = [
        SecurityContract(resource="Index HTML", source_ref="index.html:1", authentication=AuthenticationContract(required=False)),
        SecurityContract(resource="Vite Config", source_ref="vite.config.ts:1", authentication=AuthenticationContract(required=True))
    ]
    
    selector = RegressionSelector(nodes, contracts)
    result = selector.select_tests(diff)
    
    print("\n--- SELECTED TESTS ---")
    for t in result["selected_tests"]:
        print(f"- {t['contract_resource']}: {t['reason']}")
        
    print("\n--- SKIPPED TESTS ---")
    for t in result["skipped_tests"]:
        print(f"- {t['contract_resource']}: {t['reason']}")

if __name__ == "__main__":
    run_real_git_test()
