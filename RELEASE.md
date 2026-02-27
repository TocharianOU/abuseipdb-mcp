# Release Notes

## v1.0.0 – Initial Release

### Features
- **check_ip** – Check a single IP address reputation with abuse confidence score, risk level, ISP, country, and optional verbose report details
- **bulk_check** – Check up to 100 IP addresses in batch; returns flagged IPs summary sorted by confidence score
- **check_block** – Analyse all reported IPs within a CIDR network block *(requires AbuseIPDB subscription)*
- **get_blacklist** – Retrieve the AbuseIPDB threat blacklist with confidence distribution and country statistics *(requires AbuseIPDB subscription)*

### Authentication Modes
- **BYOK (Bring Your Own Key)** – Set `ABUSEIPDB_API_KEY`; requests are sent directly to `api.abuseipdb.com` using the native `Key` header
- **Hub Key (Platform Managed)** – Set `ABUSEIPDB_BASE_URL` (proxy endpoint) and `ABUSEIPDB_AUTH_TOKEN`; the platform proxy injects the real API key server-side

### Transport Modes
- **stdio** – Default mode for local MCP client integrations (Claude Desktop, etc.)
- **streamable-http** – HTTP mode for remote and multi-client deployments (`MCP_TRANSPORT=http`)
