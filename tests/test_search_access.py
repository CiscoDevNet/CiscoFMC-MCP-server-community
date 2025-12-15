from types import SimpleNamespace
from typing import Dict, List

import pytest

from sfw_mcp_fmc.config import FMCSettings
from sfw_mcp_fmc.tools.search_access import search_access_rules_impl


class StubFMCClient:
    def __init__(
        self,
        *,
        access_policies: List[Dict[str, str]],
        access_rules: Dict[str, List[Dict[str, object]]],
        domain_uuid: str = "domain-uuid",
    ) -> None:
        self._access_policies = access_policies
        self._prefilter_policies: List[Dict[str, str]] = []
        self._access_rules = access_rules
        self._prefilter_rules: Dict[str, List[Dict[str, object]]] = {}
        self._domain_uuid = domain_uuid
        self.settings = FMCSettings(
            base_url="https://lab.example.com",
            username="admin",
            password="pass",
            verify_ssl=False,
            timeout=30.0,
            domain_uuid=domain_uuid,
        )

    async def list_access_policies(self, *_, **__) -> List[Dict[str, str]]:
        return self._access_policies

    async def list_prefilter_policies(self, *_, **__) -> List[Dict[str, str]]:
        return self._prefilter_policies

    async def list_access_rules(self, policy_id: str, *_, **__) -> List[Dict[str, object]]:
        return self._access_rules.get(policy_id, [])

    async def list_prefilter_rules(self, policy_id: str, *_, **__) -> List[Dict[str, object]]:
        return self._prefilter_rules.get(policy_id, [])

    async def ensure_domain_uuid(self) -> str:
        return self._domain_uuid


@pytest.mark.asyncio
async def test_search_access_matches_network_objects(monkeypatch):
    policies = [{"id": "POLICY1", "name": "Demo"}]
    rules = {
        "POLICY1": [
            {
                "id": "RULE1",
                "name": "Allow Host",
                "action": "ALLOW",
                "enabled": True,
                "metadata": {"ruleIndex": 1, "section": "Mandatory"},
                "sourceNetworks": {"objects": [{"id": "obj-host", "name": "HostA", "type": "Host"}]},
                "destinationNetworks": {},
            }
        ]
    }
    client = StubFMCClient(access_policies=policies, access_rules=rules)

    async def fake_build_object_index(_client):
        return SimpleNamespace(
            match_objects=lambda kind, value: [
                SimpleNamespace(id="obj-host", name="HostA", type="Host")
            ]
        )

    monkeypatch.setattr("sfw_mcp_fmc.tools.search_access.build_object_index", fake_build_object_index)

    result = await search_access_rules_impl(
        indicator="192.0.2.10",
        rule_set="access",
        scope="policy",
        policy_id="policy1",
        indicator_type="ip",
        client=client,
    )

    assert result["items"], "Expected at least one matching rule"
    rule = result["items"][0]["rule"]
    assert rule["name"] == "Allow Host"
    assert rule["source_object_matches"][0]["name"] == "HostA"
    assert result["meta"]["policies_scanned"] == 1
    assert result["meta"]["indicator_type"] == "ip"


@pytest.mark.asyncio
async def test_search_access_matches_identity_objects():
    policies = [{"id": "POLICY2", "name": "Identity"}]
    rules = {
        "POLICY2": [
            {
                "id": "RULE-ID",
                "name": "SGT Rule",
                "action": "ALLOW",
                "enabled": True,
                "metadata": {"ruleIndex": 2, "section": "Mandatory"},
                "sourceNetworks": {},
                "destinationNetworks": {},
                "sourceSecurityGroupTags": {
                    "objects": [{"id": "sgt-1", "name": "Employees", "type": "ISESecurityGroupTag"}]
                },
            }
        ]
    }
    client = StubFMCClient(access_policies=policies, access_rules=rules)

    result = await search_access_rules_impl(
        indicator="Employees",
        indicator_type="sgt",
        rule_set="access",
        scope="policy",
        policy_id="POLICY2",
        client=client,
    )

    assert result["items"], "Expected SGT match"
    matches = result["items"][0]["rule"]["source_security_group_tag_matches"]
    assert matches[0]["name"] == "Employees"
    assert result["meta"]["indicator_type"] == "sgt"
