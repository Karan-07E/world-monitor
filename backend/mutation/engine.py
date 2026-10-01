import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Callable, Any, Dict
from backend.engines.models import EngineResult
from backend.findings.models import FindingLabel

class MutationEngine:
    def __init__(self, target_repo_root: str):
        self.target_repo_root = Path(target_repo_root)
        
    def create_throwaway_workspace(self) -> Path:
        """Copies the target repo to an isolated temporary directory."""
        temp_dir = Path(tempfile.mkdtemp(prefix="argus_mutant_"))
        
        # In a real environment, we would use ignore patterns for node_modules, etc.
        # to speed up copying, but for the MVP demonstration we copy the relevant files.
        try:
            # If temp_dir already exists mkdtemp ensures it's empty, 
            # so we just copy the tree. To avoid FileExistsError with copytree, 
            # we use dirs_exist_ok=True (Python 3.8+)
            shutil.copytree(self.target_repo_root, temp_dir, dirs_exist_ok=True, ignore=shutil.ignore_patterns("node_modules", ".git"))
        except Exception as e:
            # fallback if copy fails
            pass
            
        return temp_dir
        
    def apply_mutation(self, workspace_dir: Path, file_rel_path: str, search_str: str, replace_str: str) -> bool:
        """Removes or alters a security control (e.g., ownership check)."""
        target_file = workspace_dir / file_rel_path
        if not target_file.exists():
            return False
            
        content = target_file.read_text(encoding="utf-8")
        if search_str not in content:
            return False
            
        mutated_content = content.replace(search_str, replace_str)
        target_file.write_text(mutated_content, encoding="utf-8")
        return True
        
    def evaluate_mutation(
        self, 
        original_test_fn: Callable[[], EngineResult], 
        mutant_test_fn: Callable[[], EngineResult]
    ) -> Dict[str, Any]:
        """
        Confirms the generated test passes on the original and fails on the mutant.
        """
        # Run original
        original_result = original_test_fn()
        # Original should be secure (PASS or NOT APPLICABLE if not vulnerable)
        # But if we are testing a security test, we want it to block the attack (PASS)
        original_passes = (original_result.status == "PASS")
        
        # Run mutant
        mutant_result = mutant_test_fn()
        # Mutant has control removed, so the test should find the vulnerability (FAIL)
        mutant_fails = (mutant_result.status == "FAIL")
        
        is_sensitive = original_passes and mutant_fails
        
        return {
            "mutation_sensitive": is_sensitive,
            "original_status": original_result.status,
            "mutant_status": mutant_result.status,
            "label": FindingLabel.CONTROLLED_MUTATION.value if is_sensitive else None,
            "message": "Test detects control removal successfully." if is_sensitive else "Test is insensitive to control removal."
        }
    
    def cleanup_workspace(self, workspace_dir: Path):
        """Cleans up the throwaway workspace."""
        if workspace_dir.exists():
            shutil.rmtree(workspace_dir, ignore_errors=True)
