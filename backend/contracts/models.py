from pydantic import BaseModel, Field
from typing import Dict, Any, Optional

class AuthenticationContract(BaseModel):
    required: bool = True

class OwnershipContract(BaseModel):
    field: str

class OperationContract(BaseModel):
    owner_only: bool = False
    
class RoleContract(BaseModel):
    admin: str = "allowed_by_policy" # could be 'allowed', 'denied', 'allowed_by_policy'

class AnonymousContract(BaseModel):
    allowed: bool = False

class SecurityContract(BaseModel):
    resource: str
    source_ref: str = Field(..., description="A contract without a source reference is rejected.")
    authentication: Optional[AuthenticationContract] = None
    ownership: Optional[OwnershipContract] = None
    read: Optional[OperationContract] = None
    write: Optional[OperationContract] = None
    roles: Optional[RoleContract] = None
    anonymous: Optional[AnonymousContract] = None
    expected_status_codes: Optional[Dict[str, int]] = None
