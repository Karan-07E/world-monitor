import pytest
import os
import json
from pathlib import Path
from backend.db.base import Base
from backend.db.session import engine, SessionLocal
from backend.evidence.redactor import Redactor
from backend.evidence.store import EvidenceStore

@pytest.fixture(scope="module")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)

def test_redactor_jwt():
    # Simulate a JWT token string
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI.eyJzdWIiOiIxMjM0NTY3ODkwIiwibm.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    redacted = Redactor.redact_string(jwt)
    assert redacted == "[REDACTED_JWT]"
    assert jwt not in redacted

def test_redactor_dict_credentials():
    payload = {
        "user": "alice",
        "password": "super_secret_password",
        "headers": {
            "Authorization": "Bearer token123",
            "Cookie": "session=abc",
            "Accept": "application/json"
        }
    }
    redacted = Redactor.redact_dict(payload)
    
    # Should not redact non-sensitive keys
    assert redacted["user"] == "alice"
    assert redacted["headers"]["Accept"] == "application/json"
    
    # Should redact sensitive keys
    assert redacted["password"] == "[REDACTED_CREDENTIAL]"
    assert redacted["headers"]["Authorization"] == "[REDACTED_CREDENTIAL]"
    assert redacted["headers"]["Cookie"] == "[REDACTED_CREDENTIAL]"

def test_evidence_store(db_session, tmp_path):
    store = EvidenceStore(db_session, export_dir=str(tmp_path / "evidence"))
    
    req = {"headers": {"Authorization": "secret-token"}, "body": "test"}
    resp = {"status": 200, "data": "eyJh.eyJ.sig"}
    
    ev_id = store.record_evidence(
        test_id="test_horizontal_01",
        identity="User A",
        expected="ALLOW",
        observed="ALLOW",
        commit_sha="abcdef123",
        request_data=req,
        response_data=resp
    )
    
    assert ev_id.startswith("ev_")
    
    # Check disk export
    export_file = tmp_path / "evidence" / f"{ev_id}.json"
    assert export_file.exists()
    
    with open(export_file, "r") as f:
        data = json.load(f)
        
    assert data["request_data"]["headers"]["Authorization"] == "[REDACTED_CREDENTIAL]"
    assert data["response_data"]["data"] == "[REDACTED_JWT]"
    assert data["expected"] == "ALLOW"
    assert data["commit_sha"] == "abcdef123"
    assert data["finding_id"] is None
    
    # Link finding
    store.link_finding(ev_id, "AUTH-001")
    
    with open(export_file, "r") as f:
        data = json.load(f)
    assert data["finding_id"] == "AUTH-001"
