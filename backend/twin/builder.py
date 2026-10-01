import uuid
from typing import Dict, Any
from sqlalchemy.orm import Session
from backend.twin.models import TwinNode, TwinEdge
from backend.twin.schema import NodeType

def generate_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"

def populate_twin_from_recon(recon: Dict[str, Any], db: Session):
    """
    Populates the Security Twin database using facts from Phase 0 (recon).
    """
    commit_sha = recon.get("environment", {}).get("commit_sha", "unknown")
    twin_data = recon.get("twin", {})
    
def populate_twin_from_recon(recon: Dict[str, Any], db: Session):
    commit_sha = recon.get("environment", {}).get("commit_sha", "unknown")
    twin_data = recon.get("twin", {})
    
    # 1. Base Nodes
    anon_node = TwinNode(id=generate_id("id"), node_type=NodeType.IDENTITY.value, name="Anonymous", source_ref="system", commit_sha=commit_sha)
    db.add(anon_node)
    
    indicator_node = TwinNode(id=generate_id("ctrl"), node_type=NodeType.CONTROL.value, name="No Control Indicator", source_ref="system", commit_sha=commit_sha)
    db.add(indicator_node)

    # 2. Interfaces (Routes) & Edges
    routes = twin_data.get("routes", [])
    interfaces = {}
    
    for r in routes:
        if_node = TwinNode(
            id=generate_id("iface"), node_type=NodeType.INTERFACE.value, name=f"{r.get('method')} {r.get('path')}",
            source_ref=r.get('source'), commit_sha=commit_sha
        )
        interfaces[r.get('path')] = if_node
        db.add(if_node)
        
        has_any_control = False
        source_file = r.get('source').split(':')[0]
        
        if r.get("auth_line"):
            ctrl_auth = TwinNode(id=generate_id("ctrl"), node_type=NodeType.CONTROL.value, name="Authentication", source_ref=f"{source_file}:{r.get('auth_line')}", commit_sha=commit_sha)
            db.add(ctrl_auth)
            db.add(TwinEdge(id=generate_id("edge"), source_id=if_node.id, target_id=ctrl_auth.id, relationship_type="AUTHENTICATED_BY"))
            has_any_control = True
        else:
            db.add(TwinEdge(id=generate_id("edge"), source_id=anon_node.id, target_id=if_node.id, relationship_type="CAN_ACCESS"))
            
        if r.get("rl_line"):
            ctrl_rl = TwinNode(id=generate_id("ctrl"), node_type=NodeType.CONTROL.value, name="Rate Limiting", source_ref=f"{source_file}:{r.get('rl_line')}", commit_sha=commit_sha)
            db.add(ctrl_rl)
            db.add(TwinEdge(id=generate_id("edge"), source_id=if_node.id, target_id=ctrl_rl.id, relationship_type="RATE_LIMITED"))
            has_any_control = True
            
        if r.get("store_line"):
            store_node = TwinNode(id=generate_id("da"), node_type=NodeType.DATA_ASSET.value, name="Data Store", source_ref=f"{source_file}:{r.get('store_line')}", commit_sha=commit_sha)
            db.add(store_node)
            db.add(TwinEdge(id=generate_id("edge"), source_id=if_node.id, target_id=store_node.id, relationship_type="USES_STORE"))
            
        if r.get("ext_line"):
            ext_node = TwinNode(id=generate_id("da"), node_type=NodeType.DATA_ASSET.value, name="External API", source_ref=f"{source_file}:{r.get('ext_line')}", commit_sha=commit_sha)
            db.add(ext_node)
            db.add(TwinEdge(id=generate_id("edge"), source_id=if_node.id, target_id=ext_node.id, relationship_type="CALLS_EXTERNAL"))
            
        if not has_any_control:
            db.add(TwinEdge(id=generate_id("edge"), source_id=if_node.id, target_id=indicator_node.id, relationship_type="NO_CONTROL_FOUND"))

    # 3. Import Graph Edges (Module -> Module)
    imports = twin_data.get("imports", [])
    path_to_id = {r.get('source').split(':')[0]: interfaces[r.get('path')].id for r in routes}
    
    # Deduplicate module nodes to prevent exploding module counts (distinct imports only)
    module_nodes = {}
    distinct_edges = set()
    
    for imp in imports:
        from_file = imp.get("from")
        to_file = imp.get("to")
        # Simplistic match to connect files to their modules
        if from_file in path_to_id:
            edge_key = f"{from_file}->{to_file}"
            if edge_key in distinct_edges:
                continue
            distinct_edges.add(edge_key)
            
            if to_file not in module_nodes:
                imp_node = TwinNode(id=generate_id("module"), node_type="module", name=to_file, source_ref=to_file, commit_sha=commit_sha)
                db.add(imp_node)
                module_nodes[to_file] = imp_node.id
                
            db.add(TwinEdge(id=generate_id("edge"), source_id=path_to_id[from_file], target_id=module_nodes[to_file], relationship_type="IMPORTS"))
            
    db.commit()

def export_twin_to_json(db: Session) -> Dict[str, Any]:
    nodes = db.query(TwinNode).all()
    edges = db.query(TwinEdge).all()
    
    return {
        "nodes": [{
            "id": n.id,
            "node_type": n.node_type,
            "name": n.name,
            "source_ref": n.source_ref,
            "commit_sha": n.commit_sha,
            "properties": n.properties
        } for n in nodes],
        "edges": [{
            "id": e.id,
            "source_id": e.source_id,
            "target_id": e.target_id,
            "relationship_type": e.relationship_type
        } for e in edges]
    }
