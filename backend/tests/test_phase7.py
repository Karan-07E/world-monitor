import pytest
from backend.twin.schema import TwinNodeSchema, NodeType
from backend.contracts.models import SecurityContract, AuthenticationContract
from backend.regression.selector import RegressionSelector

@pytest.fixture
def regression_setup():
    nodes = [
        TwinNodeSchema(
            id="node_1", node_type=NodeType.INTERFACE, name="API Auth",
            source_ref="src/api/auth.ts:10", commit_sha="abc", properties={}
        ),
        TwinNodeSchema(
            id="node_2", node_type=NodeType.INTERFACE, name="API Profile",
            source_ref="src/api/profile.ts:25", commit_sha="abc", properties={}
        )
    ]
    contracts = [
        SecurityContract(resource="API Auth", source_ref="src/api/auth.ts:10", authentication=AuthenticationContract(required=False)),
        SecurityContract(resource="API Profile", source_ref="src/api/profile.ts:25", authentication=AuthenticationContract(required=True))
    ]
    return RegressionSelector(nodes, contracts)

def test_regression_unrelated_visual_change(regression_setup):
    diff = [{"status": "M", "a_path": "src/styles/main.css", "b_path": "src/styles/main.css", "changed_lines": [10]}]
    result = regression_setup.select_tests(diff)
    
    assert len(result["selected_tests"]) == 0
    assert len(result["skipped_tests"]) == 2
    assert "unaffected" in result_silhouette_checks(result["skipped_tests"])

def test_regression_security_change(regression_setup):
    diff = [{"status": "M", "a_path": "src/api/auth.ts", "b_path": "src/api/auth.ts", "changed_lines": [12]}]
    result = regression_setup.select_tests(diff)
    
    assert len(result["selected_tests"]) == 1
    assert result["selected_tests"][0]["contract_resource"] == "API Auth"
    assert "were modified" in result["selected_tests"][0]["reason"]
    assert len(result["skipped_tests"]) == 1

def test_regression_unmapped_new_file_failsafe(regression_setup):
    # A new .ts file is added that isn't mapped in the twin
    diff = [{"status": "A", "a_path": None, "b_path": "src/api/new_endpoint.ts", "changed_lines": [1]}]
    result = regression_setup.select_tests(diff)
    
    # Failsafe should trigger full baseline for all contracts
    assert len(result["selected_tests"]) == 2
    assert "Fail-safe triggered" in result["selected_tests"][0]["reason"]
    assert len(result["skipped_tests"]) == 0

def test_regression_lockfile_change(regression_setup):
    diff = [{"status": "M", "a_path": "package-lock.json", "b_path": "package-lock.json", "changed_lines": [100]}]
    result = regression_setup.select_tests(diff)
    
    # Should select Dependency Audit, but keep others skipped
    dep_tests = [t for t in result["selected_tests"] if t["contract_resource"] == "Dependency Audit"]
    assert len(dep_tests) == 1
    assert len(result["skipped_tests"]) == 2

def test_regression_rename_contract_source(regression_setup):
    # Rename auth.ts to auth_v2.ts
    diff = [{"status": "R", "a_path": "src/api/auth.ts", "b_path": "src/api/auth_v2.ts", "changed_lines": []}]
    result = regression_setup.select_tests(diff)
    
    # Contract should still be selected because its source was modified (renamed)
    selected = [t for t in result["selected_tests"] if t["contract_resource"] == "API Auth"]
    assert len(selected) == 1
    assert "modified" in selected[0]["reason"]

def test_regression_delete_contract_source(regression_setup):
    # Delete profile.ts
    diff = [{"status": "D", "a_path": "src/api/profile.ts", "b_path": None, "changed_lines": []}]
    result = regression_setup.select_tests(diff)
    
    selected = [t for t in result["selected_tests"] if t["contract_resource"] == "API Profile"]
    assert len(selected) == 1
    assert "DELETED" in selected[0]["reason"]

def test_regression_import_graph_selection(regression_setup):
    diff = [{"status": "M", "a_path": "src/api/auth.ts", "b_path": "src/api/auth.ts", "changed_lines": [10]}]
    # Force an unmapped file failsafe to prove it triggers
    result = regression_setup.select_tests(diff)
    assert len(result["selected_tests"]) > 0
    assert any("Unmapped" in t["reason"] for t in result["selected_tests"])

def result_silhouette_checks(skipped_tests):
    return skipped_tests[0]["reason"]
