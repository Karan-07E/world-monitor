import yaml
from typing import Dict, Any
from backend.contracts.models import SecurityContract

class ContractValidator:
    @staticmethod
    def parse_and_validate(yaml_content: str) -> SecurityContract:
        """
        Parses YAML content and validates it against the SecurityContract schema.
        Rejects contracts missing source references.
        """
        data = yaml.safe_load(yaml_content)
        if not data:
            raise ValueError("Empty contract")
            
        if "source_ref" not in data or not data["source_ref"]:
            raise ValueError("A contract without a source reference is rejected.")
            
        return SecurityContract(**data)
