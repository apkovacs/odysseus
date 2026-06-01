# Security Policy

Odysseus is a self-hosted AI workspace with privileged local capabilities. Please do not run it as a public, unauthenticated service.

## Supported Versions

Security fixes are handled on the default branch until formal releases are cut.

## Deployment Guidance

- Keep `AUTH_ENABLED=true`.
- Use HTTPS when exposing the app beyond localhost.
- Put the app behind a trusted reverse proxy or private network.
- Protect `.env`, `data/`, logs, uploaded files, generated media, and database files.
- Disable open signup unless you intentionally want new accounts.
- Keep demo/test users non-admin, and remove them entirely on serious deployments.
- Give admin accounts strong passwords and enable 2FA where possible.
- Leave high-risk agent tools restricted to admins: shell, Python, file read/write, email send/read, MCP, app API, task/skill/memory management, settings, tokens, and model serving.
- Rotate API keys, webhook secrets, and Odysseus API tokens if they appear in logs, screenshots, demos, or shared chats.
- Treat shell, model-serving, MCP, email, calendar, and vault features as privileged admin functionality.

## Preventing Local Data Leaks

Use the default `ODYSSEUS_CAPABILITY_PROFILE=workspace` for normal local use.
It keeps generic admin/API loopback tools and Browser MCP off by default,
confines file tools to configured roots, and requires local-computer access to
be explicitly enabled for shell/Python/file operations.

For stricter deployments, set:

```env
ODYSSEUS_CAPABILITY_PROFILE=private
APP_BIND=127.0.0.1
LOCALHOST_BYPASS=false
AUTH_ENABLED=true
```

To intentionally restore functionality:

- LAN/reverse-proxy access: set `APP_BIND=0.0.0.0` only behind HTTPS/VPN/reverse proxy.
- Agent access to a repo: set `ODYSSEUS_FILE_ROOTS=/path/to/repo,/path/to/workspace`.
- Secret/env access in shell/Python tools: set `ODYSSEUS_TOOL_ENV_ALLOW=NAME1,NAME2`.
- Browser automation: set `ODYSSEUS_ENABLE_BROWSER_MCP=true`.
- Legacy high-trust behavior: set `ODYSSEUS_CAPABILITY_PROFILE=full_admin`.

Application-level controls reduce accidental leaks, but shell/Python child
process egress must be contained with Docker/host firewall rules if your threat
model requires hard network isolation.

## Publishing A Fork

Before pushing a public fork, run:

```bash
git status --short
git check-ignore -v .env data/auth.json data/app.db logs/compound.log odysseus.db
git grep -n -I -E "(sk-[A-Za-z0-9_-]{20,}|xox[baprs]-|AIza[0-9A-Za-z_-]{20,}|Bearer [A-Za-z0-9._~+/-]{20,})" -- . ':!static/lib/**' ':!package-lock.json'
```

Only `.env.example`, docs, source, tests, and static assets should be committed. Never commit live `data/` contents, local databases, uploaded files, generated media, logs, backups, API keys, password hashes, or personal documents.

## Reporting

Please report vulnerabilities privately via GitHub security advisories if available, or by opening a minimal issue that does not disclose exploit details.
