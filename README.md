# Cisco Secure Firewall FMC MCP Connector

MCP server that exposes high-level tooling for Cisco Secure Firewall Management Center (FMC). Core tools:

- `list_fmc_profiles` – discover configured FMC instances.
- `find_rules_by_ip_or_fqdn` – search a specific access policy.
- `find_rules_for_target` – resolve an FTD device/HA/cluster to its assigned policies and search them.
- `search_access_rules` – FMC-wide searches with indicator + policy filters, including identity indicators (SGT, realm user/group).

## 1. Configure FMC access

### Single FMC (env mode)

Copy `.env.example` to `.env` (or export env vars) and fill in at least:

```
FMC_BASE_URL=https://<fmc-host>
FMC_USERNAME=<api-user>
FMC_PASSWORD=<password>
FMC_VERIFY_SSL=false
```

### Multiple FMCs (profile mode)

Define one env file per FMC under `profiles/`. Copy `profiles/.env.example` to a new filename (e.g., `profiles/fmc-north-south.env`) and fill it:

```
FMC_PROFILE_ID=fmc-north-south
FMC_PROFILE_DISPLAY_NAME=FMC North-South
FMC_PROFILE_ALIASES=north,north-south,10.0.0.5
FMC_BASE_URL=https://10.0.0.5
FMC_USERNAME=adminapi
FMC_PASSWORD=***
FMC_VERIFY_SSL=false
```

Point the server at this directory:

```
FMC_PROFILES_DIR=profiles
FMC_PROFILE_DEFAULT=fmc-north-south
```

When `FMC_PROFILES_DIR` is set, the server auto-loads every `*.env` file in that folder and exposes them via `list_fmc_profiles`. If it’s unset, the single-FMC env variables are used.

## 2. Run the MCP server

### Docker

```bash
docker compose up -d --build
```

The compose file expects your `.env` in the repo root (or point `env_file` at a specific profile file). Rebuild after changing `requirements.txt` or profile files.

### Local Python

You can run the server directly without Docker:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m sfw_mcp_fmc.server
```

Configure transport via `.env` (default is HTTP on `http://0.0.0.0:8000/mcp`). Logs show which FMC profiles loaded.

## 3. Manual testing

`client/test_client.py` is an interactive harness that:

1. Calls `list_fmc_profiles` to display the available FMCs and lets you select one.
2. Invokes the tools with your inputs (indicator, target, policy filters).

Run it from your host while the MCP server is up:

```bash
python client/test_client.py
```

## 4. Automated tests

Unit tests cover configuration parsing, profile discovery, and the rule-search engine (network + identity indicators). Execute locally or inside the container:

```bash
pip install -r requirements.txt   # once per environment
python -m pytest tests
```

## 5. Integrating with LLM agents

Because the server follows the MCP protocol (via FastMCP), any MCP-aware agent platform can consume it:

1. Register the MCP endpoint (stdio or HTTP). For HTTP, point to `http://<host>:8000/mcp`.
2. From the agent, call `list_fmc_profiles` to pick an FMC (by `id` or alias).
3. Call the other tools with `fmc_profile` plus your indicator/filters.
4. Consume the structured JSON responses to drive subsequent steps (summaries, remediation, follow-up searches).

This enables a single MCP instance to front multiple FMCs for humans or automated agents alike.
