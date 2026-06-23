[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/CiscoDevNet/CiscoFMC-MCP-server-community)
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

### Logging and HTTP tracing

Logging levels can be set in the active profile file (profile mode) or in the root `.env` (single-FMC mode or Docker env). The default profile’s logging values are applied at startup.

```
LOG_LEVEL=DEBUG           # overall app logging
HTTPX_TRACE=1             # log FMC request URLs and status codes
HTTPX_LOG_LEVEL=WARNING   # httpx/httpcore verbosity (default WARNING)
```

Notes:
- In profile mode, put these in the default profile file (the one named by `FMC_PROFILE_DEFAULT`).
- In Docker, the root `.env` (or `docker-compose.yml` environment) must still provide server-level settings like `FMC_PROFILES_DIR`, `FMC_PROFILE_DEFAULT`, `MCP_HOST`, and `MCP_PORT`.

## 2. Run the MCP server

### Transport selection

The transport is chosen with the `MCP_TRANSPORT` environment variable:

| `MCP_TRANSPORT` | Behavior | Typical use |
| --------------- | -------- | ----------- |
| `stdio` (default) | Server speaks MCP over stdin/stdout. No network port is opened. | Desktop MCP clients that spawn the server as a subprocess (Claude Desktop, VS Code, Cursor, etc.). |
| `http` | Server listens on `MCP_HOST`:`MCP_PORT` and serves `/mcp`. | Shared/remote deployments, Docker, multiple concurrent agents. |

If `MCP_TRANSPORT` is unset, the server starts in **stdio** mode.

### Docker

```bash
docker compose up -d --build
```

Docker deployments use the HTTP transport (set `MCP_TRANSPORT=http`, `MCP_HOST`, and `MCP_PORT` in `.env` or `docker-compose.yml`). The compose file expects your `.env` in the repo root (or point `env_file` at a specific profile file). Rebuild after changing `requirements.txt` or profile files.

### Local Python (stdio)

stdio is the default transport and the simplest way to run the server locally — an MCP-aware client launches it as a subprocess and communicates over stdin/stdout, so no port is exposed.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
MCP_TRANSPORT=stdio python -m sfw_mcp_fmc.server
```

Running the command above by hand will appear to “hang” — that is expected, because the process is waiting for an MCP client to talk to it over stdin/stdout. Normally you let your MCP client start it for you using a config like this:

```jsonc
{
  "mcpServers": {
    "cisco-fmc": {
      "command": "python",
      "args": ["-m", "sfw_mcp_fmc.server"],
      "cwd": "/absolute/path/to/CiscoFMC-MCP-server-community",
      "env": {
        "MCP_TRANSPORT": "stdio",
        "FMC_PROFILES_DIR": "profiles",
        "FMC_PROFILE_DEFAULT": "fmc-north-south"
      }
    }
  }
}
```

Notes for stdio mode:
- Point `command` at the interpreter from your virtualenv (e.g. `.venv/bin/python`) so dependencies resolve, or ensure `python` is the right one on `PATH`.
- Set `cwd` to the repo root so relative paths like `FMC_PROFILES_DIR=profiles` resolve.
- For single-FMC mode, drop the profile vars and provide `FMC_BASE_URL` / `FMC_USERNAME` / `FMC_PASSWORD` instead (in `env` or a root `.env`).
- In stdio mode the server must not print anything to stdout except MCP traffic; logging goes to stderr, so keep custom logging on stderr.

### Local Python (HTTP)

To expose the server over the network instead, opt into the HTTP transport:

```bash
MCP_TRANSPORT=http MCP_HOST=0.0.0.0 MCP_PORT=8000 python -m sfw_mcp_fmc.server
```

This serves the endpoint at `http://0.0.0.0:8000/mcp` for local/dev. When exposing it publicly, front it with HTTPS such as `https://<host>:8000/mcp`. Logs show which FMC profiles loaded.

#### Note on HTTP bearer auth

Prior README versions described `MCP_AUTH_TOKEN`, but current FastMCP clients do not enforce it reliably, so the server runs without bearer auth. If you want to continue experimenting with a token-backed flow, you can keep the env var and wire up proxy-level auth or contribute a working implementation in this repo.

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

1. Register the MCP endpoint (stdio or HTTP). For stdio, configure the client to spawn `python -m sfw_mcp_fmc.server` with `MCP_TRANSPORT=stdio` (see the stdio config example above). For HTTP, point to `https://<host>:8000/mcp` when exposed publicly (use `http://localhost:8000/mcp` for local/dev).
2. From the agent, call `list_fmc_profiles` to pick an FMC (by `id` or alias).
3. Call the other tools with `fmc_profile` plus your indicator/filters.
4. Consume the structured JSON responses to drive subsequent steps (summaries, remediation, follow-up searches).

This enables a single MCP instance to front multiple FMCs for humans or automated agents alike.
