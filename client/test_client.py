import asyncio
import json
import pprint

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

# --- CONFIG ---
SERVER_URL = "http://localhost:8000/mcp"

# Your lab specifics
#ACCESS_POLICY_ID = "0050568B-93BD-0ed3-0000-004295033038"
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

    Our MCP server returns JSON as a string, so here we:
      1. Grab first content item
      2. Read .text
      3. json.loads(...) if possible, otherwise return raw text
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
        choice = input("\nEnter 1 or 2 (default 2): ").strip() or "2"

        if choice == "1":
            query = input(
                f"Enter query (IP/CIDR/FQDN) "
                f"[default 192.168.20.25]: "
            ).strip() or "192.168.20.25"

            print("\nCalling tool: find_rules_by_ip_or_fqdn")
            raw_resp = await client.call_tool(
                "find_rules_by_ip_or_fqdn",
                {
                    "query": query,
                    "access_policy_id": ACCESS_POLICY_ID,
                },
            )
        else:
            query = input(
                f"Enter query (IP/CIDR/FQDN) "
                f"[default 192.168.20.25]: "
            ).strip() or "192.168.20.25"
            target = input(
                f"Enter target device name (FMC device name) "
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

        result = unwrap_tool_result(raw_resp)
        print("\nTool result (unwrapped):")
        pp.pprint(result)


if __name__ == "__main__":
    asyncio.run(main())
