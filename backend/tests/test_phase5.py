import pytest
from backend.findings.models import FindingSchema, TriageClass, FindingLabel, FindingStatus, BusinessImpact
from backend.findings.cvss_calc import CVSSCalculator
from backend.reports.generator import ReportGenerator
from backend.runner.retest import RetestEngine

def test_cvss_calculator():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    rationale = {"AV": "Network", "AC": "Low"}
    
    cvss_data = CVSSCalculator.calculate_from_vector(vector, rationale)
    assert cvss_data.score == 9.8
    assert cvss_data.severity == "Critical"
    assert cvss_data.rationale["AV"] == "Network"
    
def test_cvss_calculator_invalid():
    with pytest.raises(ValueError):
        CVSSCalculator.calculate_from_vector("INVALID", {})

def test_report_generator_vulnerabilities():
    cvss_data = CVSSCalculator.calculate_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", {})
    finding = FindingSchema(
        id="AUTH-001",
        title="Missing Auth",
        description="Missing check.",
        affected_component="api/users.ts:10",
        severity=cvss_data.severity,
        cvss=cvss_data,
        steps_to_reproduce=["Send GET"],
        safe_poc="GET /api/users",
        business_impact=BusinessImpact(
            affected_asset="Users", affected_roles=["Admin"], data_classification="Confidential",
            consequence_cia="Confidentiality breach", plausible_scenario="Data leak"
        ),
        remediation="Add auth.",
        evidence_id="ev_123",
        cwe="CWE-285",
        label=FindingLabel.DISCOVERED,
        triage_class=TriageClass.CONFIRMED,
        status=FindingStatus.OPEN
    )
    
    report = ReportGenerator.generate_markdown("http://localhost", "abc1234", [finding], {"Auth": "Tested"})
    assert "Missing Auth" in report
    assert "CVSS Score: 7.5" in report
    assert "1 finding(s) were discovered" in report

def test_report_generator_no_findings():
    report = ReportGenerator.generate_markdown("http://localhost", "abc1234", [], {"Auth": "Tested"})
    assert "HONEST NO-FINDING REPORT" in report
    assert "No vulnerabilities found" in report

def test_retest_engine():
    finding = FindingSchema(
        id="AUTH-002", title="Test", description="Test", affected_component="Test",
        severity="Low", cvss=CVSSCalculator.calculate_from_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", {}),
        steps_to_reproduce=[], safe_poc="", business_impact=BusinessImpact(
            affected_asset="A", affected_roles=[], data_classification="Public", consequence_cia="", plausible_scenario=""
        ), remediation="", evidence_id="ev_000", cwe="CWE-0", label=FindingLabel.DISCOVERED, triage_class=TriageClass.CONFIRMED, status=FindingStatus.OPEN
    )
    
    engine = RetestEngine()
    retested = engine.retest_finding(finding)
    assert retested.retest_result == "PASS"
    assert retested.status == FindingStatus.FIXED
