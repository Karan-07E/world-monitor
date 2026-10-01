from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class TriageClass(str, Enum):
    CONFIRMED = "CONFIRMED"
    KNOWN_REPRODUCIBLE = "KNOWN-REPRODUCIBLE"
    KNOWN_PATCHED = "KNOWN-PATCHED"
    INDICATOR = "INDICATOR"
    ASSUMPTION = "ASSUMPTION"
    HYGIENE = "HYGIENE"

class FindingLabel(str, Enum):
    DISCOVERED = "DISCOVERED"
    KNOWN = "KNOWN"
    REGRESSION = "REGRESSION"
    CONTROLLED_MUTATION = "CONTROLLED MUTATION - NOT A WORLD MONITOR FINDING"
    SELF_TEST_FIXTURE = "SELF-TEST FIXTURE"

class FindingStatus(str, Enum):
    OPEN = "OPEN"
    FIXED = "FIXED"
    NOT_REPRODUCIBLE = "NOT REPRODUCIBLE"

class CVSSData(BaseModel):
    vector: str
    score: float
    severity: str # Critical, High, Medium, Low, Info
    rationale: Dict[str, str] = Field(description="Per-metric rationale")

class BusinessImpact(BaseModel):
    affected_asset: str
    affected_roles: List[str]
    data_classification: str
    consequence_cia: str
    plausible_scenario: str

class FindingSchema(BaseModel):
    id: str
    title: str
    description: str
    affected_component: str # File:line, route, module + SHA
    severity: str
    cvss: CVSSData
    steps_to_reproduce: List[str]
    safe_poc: str
    business_impact: BusinessImpact
    remediation: str
    evidence_id: str # Link to immutable evidence
    cwe: str
    label: FindingLabel
    triage_class: TriageClass
    status: FindingStatus
    retest_result: Optional[str] = None # PASS, FAIL, or None
