import yaml
from typing import List
from backend.twin.schema import TwinGraphExport
from backend.contracts.models import (
    SecurityContract, AuthenticationContract, OwnershipContract, 
    OperationContract, RoleContract, AnonymousContract
)

def generate_contracts_from_twin(twin_data: TwinGraphExport) -> List[str]:
    """
    Proposes security contracts from the Security Twin data.
    """
    contracts = []
    
    # Simple rule: generate a contract for every INTERFACE node found in the twin
    for node in twin_data.nodes:
        if node.node_type == "interface":
            # Determine ownership field heuristically or default to "user_id"
            contract_data = {
                "resource": node.name,
                "source_ref": node.source_ref,
                "authentication": {"required": True},
                "ownership": {"field": "user_id"},
                "read": {"owner_only": True},
                "write": {"owner_only": True},
                "roles": {"admin": "allowed_by_policy"},
                "anonymous": {"allowed": False}
            }
            
            # Use yaml dump to generate the string
            contracts.append(yaml.dump(contract_data, sort_keys=False))
            
    return contracts
