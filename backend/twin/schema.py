from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from enum import Enum

class NodeType(str, Enum):
    IDENTITY = "identity"
    RESOURCE = "resource"
    INTERFACE = "interface"
    DATA_ASSET = "data_asset"
    TRUST_BOUNDARY = "trust_boundary"
    CONTROL = "control"
    MODULE = "module"

class TwinEdgeSchema(BaseModel):
    id: str
    source_id: str
    target_id: str
    relationship_type: str

class TwinNodeSchema(BaseModel):
    id: str
    node_type: NodeType
    name: str
    source_ref: str
    commit_sha: str
    properties: Dict[str, Any]

class IdentityProperties(BaseModel):
    role: str # anonymous, user, administrator, service_account

class ResourceProperties(BaseModel):
    resource_type: str # user_profile, report, article, etc.

class InterfaceProperties(BaseModel):
    protocol: str # http, mcp, ipc
    path: str
    method: Optional[str] = None

class DataAssetProperties(BaseModel):
    classification: str # public, private, restricted
    data_type: str # credential, pii, user_content

class TrustBoundaryProperties(BaseModel):
    boundary_type: str # browser_server, external_internal

class ControlProperties(BaseModel):
    control_type: str # authentication, ownership_check, validator

class TwinGraphExport(BaseModel):
    nodes: List[TwinNodeSchema]
    edges: List[TwinEdgeSchema]
