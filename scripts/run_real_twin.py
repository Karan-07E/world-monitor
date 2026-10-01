import os
from collections import Counter
from backend.twin.real_analyzer import analyze_real_repository
from backend.twin.builder import populate_twin_from_recon, export_twin_to_json
from backend.db.base import Base
from backend.db.session import engine, SessionLocal

def run():
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../target'))
    print(f"Analyzing {repo_path}...")
    
    twin_data = analyze_real_repository(repo_path)
    recon = {
        "environment": {"commit_sha": "actual_pinned_commit_sha"},
        "twin": twin_data
    }
    
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    
    populate_twin_from_recon(recon, session)
    export = export_twin_to_json(session)
    
    nodes = export["nodes"]
    edges = export["edges"]
    
    # Node Counts by Type
    type_counts = Counter([n["node_type"] for n in nodes])
    print(f"\n--- Twin Node Counts by Type ---")
    for t, count in type_counts.items():
        print(f"- {t}: {count}")
    print(f"Total Nodes: {len(nodes)}")
    
    # Edge Counts
    edge_counts = Counter([e.get("relationship_type", "unknown") for e in edges])
    print(f"\n--- Twin Edge Counts by Type ---")
    for r, count in edge_counts.items():
        print(f"- {r}: {count}")
    print(f"Total Edges: {len(edges)}")
    
    print("\n--- Sample 5 Nodes ---")
    for i, node in enumerate(nodes[:5]):
        print(f"[{i+1}] Type: {node['node_type']}, Name: {node['name']}, Source Ref: {node['source_ref']}")
        
    print("\n--- Sample 5 Edges ---")
    if edges:
        for i, edge in enumerate(edges[:5]):
            source = next((n["name"] for n in nodes if n["id"] == edge["source_id"]), "Unknown")
            target = next((n["name"] for n in nodes if n["id"] == edge["target_id"]), "Unknown")
            print(f"[{i+1}] {source} --[{edge.get('relationship_type', 'unknown')}]--> {target}")
    else:
        print("No edges generated.")
        
    session.close()

if __name__ == "__main__":
    run()
