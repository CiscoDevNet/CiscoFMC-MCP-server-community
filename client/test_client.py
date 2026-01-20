# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

import asyncio
import json
import pprint
from typing import Any, Optional

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

SERVER_URL = "http://localhost:8000/mcp"

ACCESS_POLICY_ID = ""  # optional default for option 1
DEFAULT_TARGET = "FTD-DC"

pp = pprint.PrettyPrinter(indent=2, width=100)


def _to_int(value: str, default: int) -> int:
    s = (value or "").strip()
    if not s:
        return default
    try:
        return int(s)
    except ValueError:
        return default


def _to_optional_bool(value: str) -> Optional[bool]:
    s = (value or "").strip().lower()
    if not s:
        return None
    if s in {"y", "yes", "true", "1"}:
        return True
    if s in {"n", "no", "false", "0"}:
        return False
    return None


def unwrap_tool_result(resp: Any) -> Any:
    if resp is None:
        return None
    content_list = getattr(resp, "content", None)
    if not content_list:
        return resp
    content = content_list[0]
    text = getattr(content, "text", None)
    if text is not None:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    json_payload = getattr(content, "json", None)
    if json_payload is not None:
        return json_payload
    return resp


async def main() -> None:
    print(f"Connecting to MCP server at: {SERVER_URL}\n")

    transport = StreamableHttpTransport(SERVER_URL)
    async with Client(transport=transport) as client:
        print("Testing server connectivity...")
        tools = await client.list_tools()
        print("✅ Server is reachable!\n")

        print("Available tools:")
        pp.pprint(tools)

        selected_profile: Optional[str] = None
        try:
            profiles_resp = await client.call_tool("list_fmc_profiles", {})
            profile_data = unwrap_tool_result(profiles_resp)
            if isinstance(profile_data, dict):
                profiles = profile_data.get("profiles") or []
                mode = profile_data.get("mode", "single")
                print(f"\nFMC profile mode: {mode}")
                for item in profiles:
                    pid = item.get("id")
                    display = item.get("display_name") or pid
                    aliases = item.get("aliases") or []
                    default_marker = ""
                    if item.get("default") or (
                        profile_data.get("default_profile") and item.get("id") == profile_data.get("default_profile")
                    ):
                        default_marker = " (default)"
                    print(
                        f"  - {pid}: {display}{default_marker} | base_url={item.get('base_url')} | aliases={aliases}"
                    )

                selected_profile = (
                    input(
                        "Enter FMC profile id/alias to use "
                        "(leave blank for server default): "
                    ).strip()
                    or None
                )
        except Exception as exc:
            print(f"\n⚠️  Unable to list FMC profiles: {exc}")
            selected_profile = None

        print("\nChoose what to test:")
        print("  1) find_rules_by_ip_or_fqdn (policy ID + query)")
        print("  2) find_rules_for_target (target device + query)")
        print("  3) search_access_rules (FMC-driven, across policies)")

        choice = input("Enter 1, 2, or 3 (default 3): ").strip() or "3"

        if choice == "1":
            query = input("Enter indicator (IP/CIDR/FQDN) [default 192.168.20.25]: ").strip() or "192.168.20.25"
            policy_id = input(f"Enter access policy ID [default {ACCESS_POLICY_ID or '<empty>'}]: ").strip() or ACCESS_POLICY_ID
            if not policy_id:
                print("❌ access_policy_id is required.")
                return

            print("\nCalling tool: find_rules_by_ip_or_fqdn\n")
            payload = {"query": query, "access_policy_id": policy_id}
            if selected_profile:
                payload["fmc_profile"] = selected_profile
            raw_resp = await client.call_tool("find_rules_by_ip_or_fqdn", payload)

        elif choice == "2":
            query = input("Enter indicator (IP/CIDR/FQDN/SGT/Realm user or group) [default 192.168.20.25]: ").strip() or "192.168.20.25"
            indicator_type = (
                input("Indicator type [auto/ip/subnet/fqdn/sgt/realm_user/realm_group, default auto]: ").strip() or "auto"
            )
            target = input(f"Enter target device (name/hostName) [default {DEFAULT_TARGET}]: ").strip() or DEFAULT_TARGET
            rule_set = input("Rule set [access/prefilter/both, default access]: ").strip() or "access"

            print("\nCalling tool: find_rules_for_target\n")
            payload = {
                "query": query,
                "indicator_type": indicator_type,
                "target": target,
                "rule_set": rule_set,
            }
            if selected_profile:
                payload["fmc_profile"] = selected_profile
            raw_resp = await client.call_tool("find_rules_for_target", payload)

        else:
            indicator = input("Enter indicator (IP/CIDR/FQDN/SGT/Realm user or group) [default 192.168.20.25]: ").strip() or "192.168.20.25"
            indicator_type = (
                input("Indicator type [auto/ip/subnet/fqdn/sgt/realm_user/realm_group, default auto]: ").strip() or "auto"
            )
            rule_set = input("Rule set [access/prefilter/both, default access]: ").strip() or "access"
            scope = input("Scope [fmc/policy, default fmc]: ").strip() or "fmc"

            policy_id = input("Policy ID filter (exact) [default blank]: ").strip() or None
            if scope == "policy" and not policy_id:
                policy_name = input("Policy name (exact match) [required for scope=policy unless policy_id is set]: ").strip() or None
            else:
                policy_name = input("Policy name (exact match) [default blank]: ").strip() or None

            policy_name_contains = input("Policy name contains [default blank]: ").strip() or None
            max_policies = _to_int(input("Max policies to scan (0 = all) [default 0]: ").strip(), default=0)

            rule_section = input("Rule section filter (e.g. Mandatory) [default blank]: ").strip() or None
            rule_action = input("Rule action filter (e.g. ALLOW/BLOCK/FASTPATH) [default blank]: ").strip() or None
            enabled_only = _to_optional_bool(input("Enabled only? [y/n, blank = ignore]: ").strip())
            rule_name_contains = input("Rule name contains [default blank]: ").strip() or None
            max_results = _to_int(input("Max results to return [default 100]: ").strip(), default=100)

            print("\nCalling tool: search_access_rules\n")
            payload = {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "rule_set": rule_set,
                "scope": scope,
                "policy_name": policy_name,
                "policy_id": policy_id,
                "policy_name_contains": policy_name_contains,
                "max_policies": max_policies,
                "rule_section": rule_section,
                "rule_action": rule_action,
                "enabled_only": enabled_only,
                "rule_name_contains": rule_name_contains,
                "max_results": max_results,
            }
            if selected_profile:
                payload["fmc_profile"] = selected_profile
            raw_resp = await client.call_tool("search_access_rules", payload)

        result = unwrap_tool_result(raw_resp)
        print("\nTool result (unwrapped):")
        pp.pprint(result)


if __name__ == "__main__":
    asyncio.run(main())
