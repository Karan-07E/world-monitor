from sqlalchemy import Column, String, Integer, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.db.base import Base

class TwinNode(Base):
    __tablename__ = "twin_nodes"

    id = Column(String, primary_key=True, index=True)
    node_type = Column(String, index=True) # identity, resource, interface, data_asset, trust_boundary, control
    name = Column(String, index=True)
    source_ref = Column(String) # file:line
    commit_sha = Column(String)
    properties = Column(JSON, default={})

    # Relationships
    edges_out = relationship("TwinEdge", foreign_keys='TwinEdge.source_id', back_populates="source_node")
    edges_in = relationship("TwinEdge", foreign_keys='TwinEdge.target_id', back_populates="target_node")

class TwinEdge(Base):
    __tablename__ = "twin_edges"

    id = Column(String, primary_key=True, index=True)
    source_id = Column(String, ForeignKey("twin_nodes.id"))
    target_id = Column(String, ForeignKey("twin_nodes.id"))
    relationship_type = Column(String) # e.g., "accesses", "protects", "contains"
    
    source_node = relationship("TwinNode", foreign_keys=[source_id], back_populates="edges_out")
    target_node = relationship("TwinNode", foreign_keys=[target_id], back_populates="edges_in")
