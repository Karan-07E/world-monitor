import pytest
from pathlib import Path
from backend.mutation.engine import MutationEngine
from backend.engines.models import EngineResult
from backend.findings.models import FindingLabel

def test_mutation_engine_workspace(tmp_path):
    # Setup dummy target
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "auth.ts").write_text("if (user.id !== resource.ownerId) return 403;", encoding="utf-8")
    
    engine = MutationEngine(str(target_dir))
    workspace = engine.create_throwaway_workspace()
    
    assert workspace.exists()
    assert (workspace / "auth.ts").exists()
    
    # Test apply_mutation
    success = engine.apply_mutation(
        workspace, 
        "auth.ts", 
        "if (user.id !== resource.ownerId) return 403;", 
        "// control removed"
    )
    assert success == True
    assert "// control removed" in (workspace / "auth.ts").read_text(encoding="utf-8")
    
    # Cleanup
    engine.cleanup_workspace(workspace)
    assert not workspace.exists()

def test_evaluate_mutation_sensitive():
    engine = MutationEngine("/dummy")
    
    # Mock original passing (secure)
    def mock_original():
        return EngineResult(area="Authz", check_name="Ownership", status="PASS")
        
    # Mock mutant failing (vulnerable, because control was removed)
    def mock_mutant():
        return EngineResult(area="Authz", check_name="Ownership", status="FAIL")
        
    result = engine.evaluate_mutation(mock_original, mock_mutant)
    
    assert result["mutation_sensitive"] == True
    assert result["label"] == FindingLabel.CONTROLLED_MUTATION.value

def test_evaluate_mutation_insensitive():
    engine = MutationEngine("/dummy")
    
    # Both pass -> test failed to catch the removed control
    def mock_original():
        return EngineResult(area="Authz", check_name="Ownership", status="PASS")
        
    def mock_mutant():
        return EngineResult(area="Authz", check_name="Ownership", status="PASS")
        
    result = engine.evaluate_mutation(mock_original, mock_mutant)
    
    assert result["mutation_sensitive"] == False
    assert result["label"] is None
