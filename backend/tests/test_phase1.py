import pytest
import json
from backend.db.base import Base
from backend.db.session import engine, SessionLocal
from backend.twin.builder import populate_twin_from_recon, export_twin_to_json
from backend.twin.schema import TwinGraphExport

@pytest.fixture(scope="module")
def db_session():
    # Setup in-memory SQLite DB for testing
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)

def test_populate_and_export_twin(db_session):
    # Mock recon data from Phase 0
    recon_data = {
        "environment": {"commit_sha": "abc1234"},
        "twin": {
            "auth": {"roles_exist": True},
            "routes": [{"path": "/api/test", "method": "POST", "source": "src/api.ts:25"}]
        }
    }
    
    # Populate the DB
    populate_twin_from_recon(recon_data, db_session)
    
    # Export it
    export_data = export_twin_to_json(db_session)
    
    # Validate against Pydantic schema
    twin_export = TwinGraphExport(**export_data)
    
    # Assertions
    nodes = twin_export.nodes
    assert len(nodes) > 0
    
    # Should have Anonymous, Administrator, User since roles_exist = True
    identities = [n for n in nodes if n.node_type == "identity"]
    assert len(identities) == 3
    
    # Check interfaces
    interfaces = [n for n in nodes if n.node_type == "interface"]
    assert len(interfaces) == 1
    assert interfaces[0].properties["path"] == "/api/test"
    
    # Check commit SHA is tracked
    for n in nodes:
        assert n.commit_sha == "abc1234"
