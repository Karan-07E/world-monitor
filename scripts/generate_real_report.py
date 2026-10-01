import os
from backend.reports.generator import ReportGenerator
from backend.findings.models import FindingSchema, BusinessImpact, TriageClass, FindingLabel, FindingStatus
from backend.findings.cvss_calc import CVSSCalculator
from backend.regression.git_adapter import GitAdapter

def run():
    target_url = "http://localhost:3000"
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../target'))
    adapter = GitAdapter(repo_path)
    commit_sha = adapter.repo.head.commit.hexsha
    
    cvss_data = CVSSCalculator.calculate_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", {"AV": "Network", "C": "High"})
    
    finding = FindingSchema(
        id="AUTH-BYPASS-001",
        title="Unauthenticated Access to Internal API",
        description="The API endpoint lacks authentication middleware, allowing anonymous users to query internal records.",
        affected_component="api/user/settings.ts:15",
        severity=cvss_data.severity,
        cvss=cvss_data,
        steps_to_reproduce=["Send GET request to /api/user/settings without a valid JWT", "Observe 200 OK with internal payload"],
        safe_poc="GET /api/user/settings HTTP/1.1\nHost: localhost:3000",
        business_impact=BusinessImpact(
            affected_asset="User Settings API", affected_roles=["Anonymous"], data_classification="Confidential",
            consequence_cia="Confidentiality breach", plausible_scenario="An attacker enumerates user settings."
        ),
        remediation="Enforce clerkAuth() middleware on the route.",
        evidence_id="ev_01J8",
        cwe="CWE-285",
        label=FindingLabel.SELF_TEST_FIXTURE,
        triage_class=TriageClass.CONFIRMED,
        status=FindingStatus.OPEN,
        retest_result=None
    )
    
    coverage = {
        "Authentication Engine": ["test_auth_1", "test_auth_2"],
        "Authorization Engine": ["test_authz_1", "test_authz_2", "test_authz_3", "test_authz_4"],
        "Injection/Input Validation": ["test_inj_1", "test_inj_2"],
        "Data Protection": ["test_dp_1"],
        "Client Platform Scope": [],
        "Transport / Isolation": ["test_trans_1"],
        "Dependency Audit": ["test_dep_1"]
    }
    
    report = ReportGenerator.generate_markdown(target_url, commit_sha, [finding], coverage)
    print(report)

if __name__ == "__main__":
    run()
