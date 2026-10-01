from jinja2 import Template
from typing import List, Dict, Any
from backend.findings.models import FindingSchema

REPORT_TEMPLATE = """# ARGUS-WM v3 Security Assessment Report
**Target**: {{ target_url }}
**Commit SHA**: {{ commit_sha }}

## 1. Executive Summary
{% set genuine = [] %}
{% set fixtures = [] %}
{% for f in findings %}
  {% if f.label.value == "SELF-TEST FIXTURE" %}
    {% set _ = fixtures.append(f) %}
  {% else %}
    {% set _ = genuine.append(f) %}
  {% endif %}
{% endfor %}
{% set all_engines_run = (coverage.values() | reject('equalto', []) | list | length) == (coverage | length) %}
{% if not all_engines_run %}
**PARTIALLY ASSESSED**: Not all scope engines ran successfully against the target.
{% elif genuine %}
{{ genuine|length }} genuine finding(s) were discovered during the assessment.
{% else %}
**HONEST NO-FINDING REPORT**: 0 genuine findings were discovered in the assessed scope at the given commit.
{% endif %}

## 2. Coverage & Negative Results
Below is the coverage summary computed from executed test records:
{% for area, tests in coverage.items() %}
- **{{ area }}**: {% if tests %}{{ tests|length }} Tests Executed (IDs: {{ tests | join(", ") }}){% else %}NOT ASSESSED{% endif %}
{% endfor %}

## 3. Genuine Findings
{% if genuine %}
{% for f in genuine %}
### Finding: {{ f.id }} - {{ f.title }}
- **Status**: {{ f.status.value }}
- **Label**: {{ f.label.value }}{% if f.label.value == "SELF-TEST FIXTURE" %} (No Evidence ID generated){% endif %}
- **Triage Class**: {{ f.triage_class.value }}
- **Severity**: {{ f.severity }} (CVSS Score: {{ f.cvss.score }})
- **Vector**: `{{ f.cvss.vector }}`
- **Affected Component**: `{{ f.affected_component }}`
- **CWE**: {{ f.cwe }}

**Description**:
{{ f.description }}

**Business Impact**:
Asset: {{ f.business_impact.affected_asset }}
CIA Consequence: {{ f.business_impact.consequence_cia }}
Scenario: {{ f.business_impact.plausible_scenario }}

**Steps to Reproduce**:
{% for step in f.steps_to_reproduce %}
{{ loop.index }}. {{ step }}
{% endfor %}

**Safe Proof of Concept**:
```
{{ f.safe_poc }}
```

**Remediation**:
{{ f.remediation }}

**Retest Result**: {{ f.retest_result or 'Not Retested' }}
**Evidence ID**: {% if f.label == "SELF-TEST FIXTURE" %}N/A{% else %}{{ f.evidence_id }}{% endif %}

---
{% endfor %}
{% else %}
*No genuine vulnerabilities found.*
{% endif %}

{% if fixtures %}
## 4. Self-Test Fixtures (Not Real Findings)
{% for f in fixtures %}
### [FIXTURE] {{ f.id }} - {{ f.title }}
- **Status**: {{ f.status.value }}
- **Label**: {{ f.label.value }}
- **Affected Component**: `fixture/example-route.ts:15`
- **Description**: {{ f.description }}
{% endfor %}
{% endif %}
"""

class ReportGenerator:
    @staticmethod
    def generate_markdown(target_url: str, commit_sha: str, findings: List[FindingSchema], coverage: Dict[str, str]) -> str:
        template = Template(REPORT_TEMPLATE)
        return template.render(
            target_url=target_url,
            commit_sha=commit_sha,
            findings=findings,
            coverage=coverage
        )
