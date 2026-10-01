import pytest
from backend.contracts.validator import ContractValidator
from backend.contracts.generator import generate_contracts_from_twin
from backend.contracts.compiler import ContractCompiler
from backend.twin.schema import TwinGraphExport, TwinNodeSchema, NodeType

def test_contract_validator_success():
    valid_yaml = """
    resource: /api/profile
    source_ref: src/api.ts:25
    authentication:
      required: true
    ownership:
      field: user_id
    read:
      owner_only: true
    roles:
      admin: allowed_by_policy
    anonymous:
      allowed: false
    """
    contract = ContractValidator.parse_and_validate(valid_yaml)
    assert contract.resource == "/api/profile"
    assert contract.authentication.required == True
    assert contract.source_ref == "src/api.ts:25"

def test_contract_validator_missing_source_ref():
    invalid_yaml = """
    resource: /api/profile
    authentication:
      required: true
    """
    with pytest.raises(ValueError, match="A contract without a source reference is rejected"):
        ContractValidator.parse_and_validate(invalid_yaml)

def test_generate_contracts():
    twin_data = TwinGraphExport(
        nodes=[
            TwinNodeSchema(
                id="iface_1",
                node_type=NodeType.INTERFACE,
                name="GET /api/data",
                source_ref="src/data.ts:10",
                commit_sha="abcd",
                properties={"path": "/api/data"}
            )
        ],
        edges=[]
    )
    
    contracts_yaml = generate_contracts_from_twin(twin_data)
    assert len(contracts_yaml) == 1
    
    parsed = ContractValidator.parse_and_validate(contracts_yaml[0])
    assert parsed.resource == "GET /api/data"
    assert parsed.source_ref == "src/data.ts:10"

def test_compiler_actor_matrix():
    valid_yaml = """
    resource: /api/profile
    source_ref: src/api.ts:25
    authentication:
      required: true
    read:
      owner_only: true
    roles:
      admin: allowed_by_policy
    anonymous:
      allowed: false
    """
    contract = ContractValidator.parse_and_validate(valid_yaml)
    test_cases = ContractCompiler.compile_actor_matrix(contract)
    
    # We should have 4 roles * 3 target data combinations = 12 test cases
    assert len(test_cases) == 12
    
    # Anonymous accessing own resource should be DENY
    anon_own = next(tc for tc in test_cases if tc["actor"] == "Anonymous" and tc["target_data"] == "own_resource")
    assert anon_own["expected"] == "DENY"
    
    # User A accessing other_resource should be DENY
    user_other = next(tc for tc in test_cases if tc["actor"] == "User A" and tc["target_data"] == "other_resource")
    assert user_other["expected"] == "DENY"
    
    # Admin accessing admin_operation should be ALLOW
    admin_op = next(tc for tc in test_cases if tc["actor"] == "Admin" and tc["target_data"] == "admin_operation")
    assert admin_op["expected"] == "ALLOW"
