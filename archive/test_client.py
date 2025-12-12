import asyncio
import json
import pprint

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

# --- CONFIG ---
SERVER_URL = "http://localhost:8000/mcp"

# Your lab specifics
# ACCESS_POLICY_ID = "0050568B-93BD-0ed3-0000-004295033038"
ACCESS_POLICY_ID = ""
DEFAULT_TARGET = "FTD-DC"

pp = pprint.PrettyPrinter(indent=2, width=100)


def unwrap_tool_result(resp):
    """
    Safely unwrap the content from a FastMCP tool call result.

    FastMCP's HTTP client returns a ToolResponse with .content list.
    Each item is usually a TextContent(BaseModel) with:

        - .type (e.g. "text")
        - .text (string payload from server)

    Our MCP server returns JSON as a string for some tools, so here we:
      1. Grab first content item
      2. Read .text
      3. json.loads(...) if possible, otherwise return raw text

    For tools that already return a dict (e.g. search_access_rules),
    FastMCP will send JSON directly and .text may be None. In that case
    we fall back to .json or .model_dump().
    """
    if not hasattr(resp, "content") or not resp.content:
        return resp

    content = resp.content[0]

    # Prefer .text for TextContent
    text = getattr(content, "text", None)
    if text is not None:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    # Fallback: if server ever uses JSON content type directly
    json_payload = getattr(content, "json", None)
    if isinstance(json_payload, (dict, list)):
        return json_payload

    # As a last resort, return the pydantic model as dict
    try:
        return content.model_dump()
    except Exception:
        return content


async def main() -> None:
    transport = StreamableHttpTransport(url=SERVER_URL)
    client = Client(transport)

    print(f"\nConnecting to MCP server at: {SERVER_URL}")
    async with client:
        # 1) Ping
        print("\nTesting server connectivity...")
        await client.ping()
        print("✅ Server is reachable!\n")

        # 2) List tools
        print("Available tools:")
        tools = await client.list_tools()
        pp.pprint(tools)

        # --- Simple menu for testing ---
        print("\nChoose what to test:")
        print("  1) find_rules_by_ip_or_fqdn (policy ID + query)")
        print("  2) find_rules_for_target (target device + query)")
        print("  3) search_access_rules (FMC-driven, across policies)")
        choice = input("\nEnter 1, 2, or 3 (default 3): ").strip() or "3"

        if choice == "1":
            if not ACCESS_POLICY_ID:
                print(
                    "\n[!] ACCESS_POLICY_ID is empty. "
                    "Set it in test_client.py before using option 1.\n"
                )
                return

            query = input(
                "Enter query (IP/CIDR/FQDN) [default 192.168.20.25]: "
            ).strip() or "192.168.20.25"

            print("\nCalling tool: find_rules_by_ip_or_fqdn")
            raw_resp = await client.call_tool(
                "find_rules_by_ip_or_fqdn",
                {
                    "query": query,
                    "access_policy_id": ACCESS_POLICY_ID,
                },
            )

        elif choice == "2":
            query = input(
                "Enter query (IP/CIDR/FQDN) [default 192.168.20.25]: "
            ).strip() or "192.168.20.25"
            target = input(
                f"Enter target device name (FMC device/HA/cluster name) "
                f"[default {DEFAULT_TARGET}]: "
            ).strip() or DEFAULT_TARGET

            print("\nCalling tool: find_rules_for_target")
            raw_resp = await client.call_tool(
                "find_rules_for_target",
                {
                    "query": query,
                    "target": target,
                },
            )

        else:
            # FMC-driven search_access_rules
            indicator = input(
                "Enter indicator (IP/CIDR/FQDN) [default 192.168.20.25]: "
            ).strip() or "192.168.20.25"

            indicator_type = input(
                "Indicator type [auto/ip/subnet/fqdn, default auto]: "
            ).strip().lower() or "auto"
            if indicator_type not in ("auto", "ip", "subnet", "fqdn"):
                print("[!] Invalid indicator_type, using 'auto'")
                indicator_type = "auto"

            scope = input(
                "Scope [fmc/policy, default fmc]: "
            ).strip().lower() or "fmc"
            if scope not in ("fmc", "policy"):
                print("[!] Invalid scope, using 'fmc'")
                scope = "fmc"

            policy_name = None
            if scope == "policy":
                policy_name = input(
                    "Enter Access Policy name (exact match): "
                ).strip()
                if not policy_name:
                    print("[!] Empty policy_name with scope='policy' - aborting.")
                    return

            max_results_str = input(
                "Max results to return [default 100]: "
            ).strip() or "100"
            try:
                max_results = int(max_results_str)
            except ValueError:
                print("[!] Invalid max_results, using 100")
                max_results = 100

            print("\nCalling tool: search_access_rules")
            raw_resp = await client.call_tool(
                "search_access_rules",
                {
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "scope": scope,
                    "policy_name": policy_name,
                    "max_results": max_results,
                },
            )

        result = unwrap_tool_result(raw_resp)
        print("\nTool result (unwrapped):")
        pp.pprint(result)


if __name__ == "__main__":
    asyncio.run(main())
