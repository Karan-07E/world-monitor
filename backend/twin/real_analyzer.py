import re
from pathlib import Path
from typing import Dict, Any, List

def extract_real_routes_and_auth(repo_root: str) -> Dict[str, Any]:
    """
    Regex and string-matching based AST extractor. (No Tree-sitter is used here; regex is used for portability and speed).
    Known limitations: does not handle dynamic imports, re-exports across files, or complex path aliases perfectly.
    """
    repo_path = Path(repo_root)
    routes = {}
    imports = []
    
    excluded_dirs = {"node_modules", "dist", ".git", "tests"}
    dirs_to_scan = [repo_path / "api", repo_path / "convex", repo_path / "src-tauri", repo_path / "cli", repo_path / "sdk"]
    
    for d in dirs_to_scan:
        if not d.exists(): continue
        for filepath in d.rglob("*"):
            if not filepath.is_file() or not filepath.name.endswith((".ts", ".js", ".mjs", ".cjs", ".rs", ".go", ".py")):
                continue
            if any(p in filepath.parts for p in excluded_dirs): continue
            if filepath.name.endswith((".d.ts", ".test.ts", ".spec.ts")): continue
            
            # Exclude catch-all fallback routes like [...notfound]
            if "not-found" in filepath.name or "fallback" in filepath.name or "[..." in filepath.name:
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
                lines = content.split('\n')
                
                # Determine relative path
                rel_posix = filepath.relative_to(repo_path).as_posix()
                
                # Default GET unless POST/PUT/DELETE explicitly matched
                method = "GET"
                if "req.method === 'POST'" in content or "POST" in content or "mutation(" in content: method = "POST"
                elif "req.method === 'PUT'" in content: method = "PUT"
                elif "req.method === 'DELETE'" in content: method = "DELETE"
                
                auth_line, store_line, ext_line, rl_line = None, None, None, None
                
                for i, line in enumerate(lines):
                    if not auth_line and ("validateBearerToken" in line or "validateSessionToken" in line or "validateKey" in line or "requireAuth" in line or "auth()" in line): auth_line = i + 1
                    if not store_line and ("convex" in line.lower() or "redis" in line.lower() or "db" in line.lower()): store_line = i + 1
                    if not ext_line and ("fetch(" in line or "axios" in line): ext_line = i + 1
                    if not rl_line and ("RateLimit" in line or "upstash" in line.lower()): rl_line = i + 1
                    
                    import_match = re.search(r'(?:import\s+.*from\s+|require\()\s*[\'"]([^\'"]+)[\'"]', line)
                    if import_match:
                        imported_module = import_match.group(1)
                        if imported_module.startswith("."):
                            # Resolve relative path
                            current_dir = Path(filepath).parent
                            resolved_path = (current_dir / imported_module).resolve()
                            try:
                                resolved_rel = resolved_path.relative_to(repo_path).as_posix()
                                # Add extension if missing
                                if not resolved_rel.endswith((".ts", ".js", ".mjs", ".cjs", ".json")):
                                    if (repo_path / f"{resolved_rel}.ts").exists(): resolved_rel += ".ts"
                                    elif (repo_path / f"{resolved_rel}.js").exists(): resolved_rel += ".js"
                                imports.append({"from": rel_posix, "to": resolved_rel})
                            except ValueError:
                                pass
                        elif imported_module.startswith("~/") or imported_module.startswith("@/"):
                            # Resolve alias mapping assuming ~ or @ is repo root
                            resolved_rel = imported_module[2:]
                            if not resolved_rel.endswith((".ts", ".js", ".mjs", ".cjs", ".json")):
                                if (repo_path / f"{resolved_rel}.ts").exists(): resolved_rel += ".ts"
                                elif (repo_path / f"{resolved_rel}.js").exists(): resolved_rel += ".js"
                            imports.append({"from": rel_posix, "to": resolved_rel})

                    # If this file exports a route handler or CLI command or Tauri command
                    is_route = ("export default" in line or "export async function" in line or "query(" in line or "mutation(" in line or "#[tauri::command]" in line)
                    
                    if is_route:
                        route_path = f"/{rel_posix.replace('.ts', '').replace('.js', '').replace('.rs', '')}"
                        # Skip if it is a helper file (starts with _) but we still scan it for imports
                        if not filepath.name.startswith("_"):
                            if route_path not in routes:
                                routes[route_path] = {
                                    "path": route_path,
                                    "method": method,
                                    "source": f"{rel_posix}:{i+1}",
                                    "auth_line": auth_line,
                                    "store_line": store_line,
                                    "ext_line": ext_line,
                                    "rl_line": rl_line
                                }
            except Exception:
                pass

    return {
        "routes": list(routes.values()),
        "imports": imports
    }

def analyze_real_repository(repo_root: str) -> Dict[str, Any]:
    return extract_real_routes_and_auth(repo_root)
