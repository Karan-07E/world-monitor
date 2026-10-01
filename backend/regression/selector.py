from typing import List, Dict, Any, Set
from backend.twin.schema import TwinNodeSchema, TwinEdgeSchema
from backend.contracts.models import SecurityContract

class RegressionSelector:
    def __init__(self, twin_nodes: List[TwinNodeSchema], twin_edges: List[TwinEdgeSchema], contracts: List[SecurityContract]):
        self.twin_nodes = twin_nodes
        self.twin_edges = twin_edges
        self.contracts = contracts

    def select_tests(self, diff_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        selected = []
        skipped = []
        
        file_to_nodes = {}
        node_by_id = {}
        for node in self.twin_nodes:
            node_by_id[node.id] = node
            file_path = node.source_ref.split(":")[0] if ":" in node.source_ref else node.source_ref
            if file_path not in file_to_nodes:
                file_to_nodes[file_path] = []
            file_to_nodes[file_path].append(node)
            
        # Build adjacency list (target -> source) because we want to know what imports the changed module
        # IMPORTS: source (module A) -> target (module B). If B changes, A is affected.
        # So we want an edge from B -> A.
        adj = {}
        for edge in self.twin_edges:
            # We want to traverse backwards for IMPORTS (if target changes, source is affected)
            if edge.relationship_type == "IMPORTS":
                if edge.target_id not in adj: adj[edge.target_id] = []
                adj[edge.target_id].append(edge.source_id)
            elif edge.relationship_type in ["AUTHENTICATED_BY", "RATE_LIMITED", "USES_STORE"]:
                # If control changes (target), the interface (source) is affected.
                if edge.target_id not in adj: adj[edge.target_id] = []
                adj[edge.target_id].append(edge.source_id)
            
        affected_node_ids = set()
        unmapped_files_changed = False
        dependency_changed = False
        tauri_changed = False
        docker_changed = False
        
        contract_source_updates = {}
        
        for diff in diff_results:
            status = diff["status"]
            a_path = diff["a_path"]
            b_path = diff["b_path"]
            
            active_path = b_path if b_path else a_path
            
            if active_path.endswith("package.json") or "lock" in active_path:
                dependency_changed = True
                continue
            if "tauri.conf.json" in active_path:
                tauri_changed = True
                continue
            if "Dockerfile" in active_path or "docker-compose" in active_path:
                docker_changed = True
                continue
                
            if active_path.endswith((".css", ".html", ".md", ".png", ".jpg", ".svg", ".ico")):
                continue
                
            if status == "R":
                contract_source_updates[a_path] = b_path
                
            if status == "D":
                contract_source_updates[a_path] = None
                
            mapped = False
            for path_to_check in [a_path, b_path]:
                if path_to_check and path_to_check in file_to_nodes:
                    for n in file_to_nodes[path_to_check]: 
                        affected_node_ids.add(n.id)
                    mapped = True
                    
            if not mapped and active_path.endswith((".ts", ".js", ".tsx", ".jsx", ".py", ".go")):
                if active_path.startswith("scripts/") or active_path.startswith("config/") or active_path.startswith("."):
                    continue
                unmapped_files_changed = True

        # BFS to find all affected nodes via graph
        queue = list(affected_node_ids)
        visited = set(affected_node_ids)
        while queue:
            curr = queue.pop(0)
            for neighbor in adj.get(curr, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
                    
        affected_node_ids = visited

        affected_contract_refs = set()
        for nid in affected_node_ids:
            if nid in node_by_id:
                node = node_by_id[nid]
                affected_contract_refs.add(node.source_ref.split(":")[0] if ":" in node.source_ref else node.source_ref)

        for contract in self.contracts:
            c_file = contract.source_ref.split(":")[0] if ":" in contract.source_ref else contract.source_ref
            
            if c_file in contract_source_updates:
                new_path = contract_source_updates[c_file]
                if new_path is None:
                    selected.append({"contract_resource": contract.resource, "reason": f"Contract source '{contract.source_ref}' was DELETED. Running contract to ensure fail-safe.", "status": "SELECTED"})
                    continue
                else:
                    c_file = new_path
                    affected_contract_refs.add(c_file)
            
            if unmapped_files_changed:
                selected.append({"contract_resource": contract.resource, "reason": "Fail-safe triggered: Unmapped source files changed. Running full baseline.", "status": "SELECTED"})
            elif c_file in affected_contract_refs:
                selected.append({"contract_resource": contract.resource, "reason": f"Contract source '{contract.source_ref}' or its dependencies were modified.", "status": "SELECTED"})
            else:
                skipped.append({"contract_resource": contract.resource, "reason": f"Contract source '{contract.source_ref}' is unaffected by the current diff.", "status": "SKIPPED"})
                
        if dependency_changed:
            selected.append({"contract_resource": "Dependency Audit", "reason": "Lockfile or package.json changed.", "status": "SELECTED"})
        if tauri_changed:
            selected.append({"contract_resource": "Client Platform Scope", "reason": "Tauri config changed.", "status": "SELECTED"})
        if docker_changed:
            selected.append({"contract_resource": "Transport / Isolation", "reason": "Docker configuration changed.", "status": "SELECTED"})
            
        return {"selected_tests": selected, "skipped_tests": skipped}
