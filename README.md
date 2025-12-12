# Cisco Secure Firewall FMC MCP Connector

Local-only project providing MCP tools to query Cisco FMC:

- `find_rules_by_ip_or_fqdn`
- `find_rules_for_target` (resolves device / HA pair / cluster, then finds rules)
- `search_access_rules` (FMC-wide search across policies, with prefilters)

## Quick start (Docker)

1) Create `.env` from the template:
- copy `.env.example` to `.env`
- set `FMC_BASE_URL`, `FMC_USERNAME`, `FMC_PASSWORD`

2) Run:
```bash
docker compose up -d --build
