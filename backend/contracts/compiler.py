from typing import List, Dict, Any
from backend.contracts.models import SecurityContract

class ContractCompiler:
    @staticmethod
    def compile_actor_matrix(contract: SecurityContract) -> List[Dict[str, Any]]:
        """
        Compiles the contract into executable test case definitions based on the 
        Actor matrix (Anonymous, User A, User B, Admin).
        """
        test_cases = []
        
        roles = ["Anonymous", "User A", "User B", "Admin"]
        
        for role in roles:
            # Horizontal & Vertical combinations
            # Testing own resource vs other-user resource vs admin operations
            
            # 1. Own resource access
            if role == "Anonymous":
                own_expect = "ALLOW" if (contract.anonymous and contract.anonymous.allowed) else "DENY"
            elif role == "Admin":
                # Admin resolution rule: from policy/source. Default to ASSUMPTION if undefined
                own_expect = "ASSUMPTION" if contract.roles.admin == "allowed_by_policy" else "ALLOW"
            else:
                own_expect = "ALLOW" if contract.authentication.required else "ALLOW"
                
            test_cases.append({
                "resource": contract.resource,
                "actor": role,
                "target_data": "own_resource",
                "expected": own_expect
            })
            
            # 2. Other-user resource (Horizontal access A -> B)
            if role == "Anonymous":
                other_expect = "ALLOW" if (contract.anonymous and contract.anonymous.allowed) else "DENY"
            elif role in ["User A", "User B"]:
                other_expect = "DENY" if (contract.read and contract.read.owner_only) else "ALLOW"
            elif role == "Admin":
                other_expect = "ASSUMPTION" if contract.roles.admin == "allowed_by_policy" else "ALLOW"
                
            test_cases.append({
                "resource": contract.resource,
                "actor": role,
                "target_data": "other_resource",
                "expected": other_expect
            })
            
            # 3. Admin-only operation (Vertical)
            if role in ["Anonymous", "User A", "User B"]:
                admin_expect = "DENY"
            elif role == "Admin":
                admin_expect = "ALLOW"
                
            test_cases.append({
                "resource": contract.resource,
                "actor": role,
                "target_data": "admin_operation",
                "expected": admin_expect
            })

        return test_cases
