from cvss import CVSS3
from backend.findings.models import CVSSData
from typing import Dict

class CVSSCalculator:
    @staticmethod
    def calculate_from_vector(vector_string: str, rationale: Dict[str, str]) -> CVSSData:
        """
        Parses a CVSS v3.1 vector string, calculates the score and severity,
        and attaches the per-metric rationale.
        Example vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        """
        try:
            cvss_obj = CVSS3(vector_string)
            score = cvss_obj.scores()[0] # Base score
            severity = cvss_obj.severities()[0]
            
            return CVSSData(
                vector=cvss_obj.clean_vector(),
                score=score,
                severity=severity,
                rationale=rationale
            )
        except Exception as e:
            raise ValueError(f"Invalid CVSS vector: {vector_string}. Error: {str(e)}")
