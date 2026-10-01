from pydantic import BaseModel
from typing import Optional, Any, Dict, List

class EngineResult(BaseModel):
    area: str
    check_name: str
    status: str # PASS, FAIL, NOT APPLICABLE, ERROR
    evidence: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    finding_summary: Optional[str] = None
