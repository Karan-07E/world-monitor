import subprocess
from typing import List, Dict, Any

class RealGitAdapter:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def get_diff(self, old_sha: str, new_sha: str) -> List[Dict[str, Any]]:
        # Get name-status
        cmd = ["git", "diff", "--name-status", old_sha, new_sha]
        try:
            res = subprocess.run(cmd, cwd=self.repo_path, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError:
            return []
            
        diff_list = []
        for line in res.stdout.strip().split("\n"):
            if not line: continue
            parts = line.split("\t")
            status_char = parts[0][0] # M, A, D, R
            
            if status_char == "R":
                a_path = parts[1]
                b_path = parts[2]
            else:
                a_path = parts[1]
                b_path = parts[1]
                
            # For simplicity, we won't extract exact changed lines here since the selector mainly works on file paths.
            # We'll just put [1] for now, unless changed_lines are strictly required by the selector rules.
            # A real implementation would parse `git diff -U0` to get line ranges.
            
            diff_list.append({
                "status": status_char,
                "a_path": a_path,
                "b_path": b_path,
                "changed_lines": [1] # Stubbed for now, full line parsing is complex and not fully utilized yet
            })
            
        return diff_list
