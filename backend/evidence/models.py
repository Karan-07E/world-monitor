from sqlalchemy import Column, String, JSON
from backend.db.base import Base

class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(String, primary_key=True, index=True)
    test_id = Column(String, index=True) # ID mapping to the specific execution test
    finding_id = Column(String, index=True, nullable=True) # Linked finding, if any
    
    # Redacted evidence payload
    request_data = Column(JSON)
    response_data = Column(JSON)
    
    identity = Column(String)
    expected = Column(String)
    observed = Column(String)
    
    timestamp = Column(String)
    commit_sha = Column(String)
