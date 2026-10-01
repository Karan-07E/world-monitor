import uuid
import json
from pathlib import Path
from sqlalchemy.orm import Session
from backend.evidence.models import EvidenceRecord
from backend.evidence.redactor import Redactor
from datetime import datetime

class EvidenceStore:
    def __init__(self, db: Session, export_dir: str = "evidence"):
        self.db = db
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)
        
    def record_evidence(
        self, 
        test_id: str, 
        identity: str, 
        expected: str, 
        observed: str, 
        commit_sha: str, 
        request_data: dict, 
        response_data: dict
    ) -> str:
        """
        Redacts and securely stores evidence immutably.
        """
        # Redact data
        safe_req = Redactor.redact_dict(request_data)
        safe_resp = Redactor.redact_dict(response_data)
        
        evidence_id = f"ev_{uuid.uuid4().hex[:8]}"
        from datetime import timezone
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        record = EvidenceRecord(
            id=evidence_id,
            test_id=test_id,
            identity=identity,
            expected=expected,
            observed=observed,
            timestamp=timestamp,
            commit_sha=commit_sha,
            request_data=safe_req,
            response_data=safe_resp
        )
        
        # Save to DB
        self.db.add(record)
        self.db.commit()
        
        # Export securely to disk
        self._export_to_disk(record)
        
        return evidence_id
        
    def _export_to_disk(self, record: EvidenceRecord):
        file_path = self.export_dir / f"{record.id}.json"
        
        export_data = {
            "id": record.id,
            "test_id": record.test_id,
            "finding_id": record.finding_id,
            "identity": record.identity,
            "expected": record.expected,
            "observed": record.observed,
            "timestamp": record.timestamp,
            "commit_sha": record.commit_sha,
            "request_data": record.request_data,
            "response_data": record.response_data
        }
        
        with open(file_path, "w") as f:
            json.dump(export_data, f, indent=2)

    def link_finding(self, evidence_id: str, finding_id: str):
        """Links an existing evidence record to a final finding."""
        record = self.db.query(EvidenceRecord).filter(EvidenceRecord.id == evidence_id).first()
        if not record:
            raise ValueError(f"Evidence {evidence_id} not found.")
            
        record.finding_id = finding_id
        self.db.commit()
        
        # Update disk export
        self._export_to_disk(record)
