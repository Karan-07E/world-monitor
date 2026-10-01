import pytest
from backend.regression.selector import RegressionSelector
from backend.contracts.models import SecurityContract
from backend.twin.schema import TwinNodeSchema

@pytest.fixture
def regression_setup():
    nodes = [
        TwinNodeSchema(id="n1", node_type="interface", name="GET /api/test", source_ref="api/test.ts:10", commit_sha="abc", properties={}),
        TwinNodeSchema(id="n2", node_type="module", name="scripts/build.js", source_ref="scripts/build.js", commit_sha="abc", properties={}),
        TwinNodeSchema(id="n3", node_type="module", name="package.json", source_ref="package.json", commit_sha="abc", properties={})
    ]
    contracts = [
        SecurityContract(resource="GET /api/test", source_ref="api/test.ts:10", coverage_tier="Tier 1", rules=[]),
        SecurityContract(resource="Client Platform Scope", source_ref="src-tauri/tauri.conf.json", coverage_tier="Tier 1", rules=[]),
        SecurityContract(resource="Dependency Audit", source_ref="package.json", coverage_tier="Tier 1", rules=[])
    ]
    return RegressionSelector(twin_nodes=nodes, twin_edges=[], contracts=contracts)

def test_selector_docs_visual(regression_setup):
    diff = [{"status": "M", "a_path": "public/style.css", "b_path": "public/style.css", "changed_lines": [1]}]
    res = regression_setup.select_tests(diff)
    assert len(res["selected_tests"]) == 0

def test_selector_dependency_audit(regression_setup):
    diff = [{"status": "M", "a_path": "package-lock.json", "b_path": "package-lock.json", "changed_lines": [1]}]
    res = regression_setup.select_tests(diff)
    assert any(t["contract_resource"] == "Dependency Audit" for t in res["selected_tests"])

def test_selector_scripts_failsafe(regression_setup):
    # scripts/ shouldn't trigger the unmapped fallback
    diff = [{"status": "M", "a_path": "scripts/deploy.sh", "b_path": "scripts/deploy.sh", "changed_lines": [1]}]
    res = regression_setup.select_tests(diff)
    assert not any("Unmapped" in t["reason"] for t in res["selected_tests"])

def test_selector_contract_coverage(regression_setup):
    diff = [{"status": "M", "a_path": "api/test.ts", "b_path": "api/test.ts", "changed_lines": [10]}]
    res = regression_setup.select_tests(diff)
    assert len(res["selected_tests"]) == 1
    assert res["selected_tests"][0]["contract_resource"] == "GET /api/test"
