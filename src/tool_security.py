"""Server-side tool safety policy."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, Set

logger = logging.getLogger(__name__)

CAPABILITY_PROFILES = {"private", "workspace", "developer", "full_admin"}

LOCAL_COMPUTER_TOOLS = {
    "bash",
    "python",
    "read_file",
    "write_file",
}

# Tools that are equivalent to broad local/admin authority or generic network
# egress. Keep them behind explicit opt-in outside full-admin mode.
HIGH_RISK_AGENT_TOOLS = {
    "api_call",
    "app_api",
    "manage_mcp",
    "manage_webhooks",
    "manage_tokens",
    "manage_settings",
    "download_model",
    "serve_model",
    "stop_served_model",
    "cancel_download",
    "adopt_served_model",
    "builtin_browser",
}

PRIVATE_PROFILE_BLOCKED_TOOLS = (
    LOCAL_COMPUTER_TOOLS
    | HIGH_RISK_AGENT_TOOLS
    | {
        "web_search",
        "trigger_research",
        "manage_research",
        "send_email",
        "reply_to_email",
        "bulk_email",
    }
)

WORKSPACE_PROFILE_BLOCKED_TOOLS = {
    "api_call",
    "app_api",
    "manage_mcp",
    "manage_webhooks",
    "manage_tokens",
    "manage_settings",
    "download_model",
    "serve_model",
    "stop_served_model",
    "cancel_download",
    "adopt_served_model",
    "builtin_browser",
}

SECRET_ENV_RE = re.compile(
    r"(key|token|secret|password|passwd|credential|cookie|auth|session)",
    re.IGNORECASE,
)

SENSITIVE_PATH_PARTS = {
    ".env",
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".gcloud",
    ".kube",
    ".docker",
    "keychain",
    "cookies",
}

SENSITIVE_FILENAMES = {
    "auth.json",
    "sessions.json",
    ".app_key",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
}


def capability_profile() -> str:
    """Return the active capability profile.

    Environment wins so operators can force a deployment-wide posture even if
    data/settings.json is stale or user-editable.
    """
    raw = os.environ.get("ODYSSEUS_CAPABILITY_PROFILE")
    if not raw:
        try:
            from src.settings import get_setting
            raw = get_setting("capability_profile", "workspace")
        except Exception:
            raw = "workspace"
    prof = (raw or "workspace").strip().lower()
    if prof not in CAPABILITY_PROFILES:
        logger.warning("Unknown ODYSSEUS_CAPABILITY_PROFILE=%r; using workspace", raw)
        return "workspace"
    return prof


def profile_blocked_tools() -> Set[str]:
    prof = capability_profile()
    if prof == "private":
        return set(PRIVATE_PROFILE_BLOCKED_TOOLS)
    if prof == "workspace":
        return set(WORKSPACE_PROFILE_BLOCKED_TOOLS)
    return set()


def profile_blocks_mcp() -> bool:
    return capability_profile() == "private"


def browser_mcp_enabled() -> bool:
    raw = os.environ.get("ODYSSEUS_ENABLE_BROWSER_MCP")
    if raw is not None:
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if capability_profile() == "full_admin":
        return True
    try:
        from src.settings import get_setting
        return bool(get_setting("browser_mcp_enabled", False))
    except Exception:
        return False


def _split_csv_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [p.strip() for p in raw.split(",") if p.strip()]


def configured_file_roots() -> list[Path]:
    roots = _split_csv_env("ODYSSEUS_FILE_ROOTS")
    if not roots:
        try:
            from src.settings import get_setting
            saved = get_setting("file_roots", ["./data/workspace"])
            roots = saved if isinstance(saved, list) else [str(saved)]
        except Exception:
            roots = ["./data/workspace"]
    out: list[Path] = []
    for root in roots:
        try:
            p = Path(root).expanduser()
            if not p.is_absolute():
                p = Path.cwd() / p
            out.append(p.resolve(strict=False))
        except Exception:
            logger.warning("Ignoring invalid file root: %r", root)
    return out or [(Path.cwd() / "data" / "workspace").resolve(strict=False)]


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _looks_sensitive(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if parts & SENSITIVE_PATH_PARTS:
        return True
    return path.name.lower() in SENSITIVE_FILENAMES


def resolve_tool_path(raw_path: str, *, for_write: bool = False) -> Path:
    """Resolve a tool file path inside configured roots.

    Relative paths are anchored at the first root. Absolute paths are allowed
    only if they resolve under one configured root. Symlinks are resolved for
    existing files/directories; non-existent write targets are checked via the
    resolved parent plus target name.
    """
    if not raw_path or not raw_path.strip():
        raise ValueError("path required")
    if capability_profile() == "full_admin":
        p = Path(raw_path).expanduser()
        return p.resolve(strict=not for_write)
    roots = configured_file_roots()
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = roots[0] / candidate
    if for_write:
        parent = candidate.parent.resolve(strict=False)
        resolved = parent / candidate.name
    else:
        resolved = candidate.resolve(strict=True)
    if _looks_sensitive(resolved):
        raise PermissionError(f"blocked sensitive path: {raw_path}")
    if not any(_is_relative_to(resolved, root) for root in roots):
        roots_txt = ", ".join(str(r) for r in roots)
        raise PermissionError(f"path is outside configured file roots ({roots_txt})")
    return resolved


def safe_tool_env() -> dict[str, str]:
    """Build a minimal subprocess environment for tool execution."""
    allow = set(_split_csv_env("ODYSSEUS_TOOL_ENV_ALLOW"))
    if not allow:
        try:
            from src.settings import get_setting
            saved = get_setting("tool_env_allow", [])
            allow.update(str(x) for x in saved if x)
        except Exception:
            pass
    base_allow = {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "SHELL",
        "TMPDIR",
        "USER",
    }
    env = {}
    for key, val in os.environ.items():
        if key in base_allow or key in allow:
            if SECRET_ENV_RE.search(key) and key not in allow:
                continue
            env[key] = val
    env.update({
        "TERM": "xterm-256color",
        "COLUMNS": "120",
        "LINES": "40",
    })
    return env


def tool_cwd() -> str:
    root = configured_file_roots()[0]
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def configured_net_allowlist() -> set[str]:
    allowed = set(_split_csv_env("ODYSSEUS_TOOL_NET_ALLOW"))
    if not allowed:
        try:
            from src.settings import get_setting
            saved = get_setting("tool_net_allow", [])
            allowed.update(str(x).strip() for x in saved if str(x).strip())
        except Exception:
            pass
    return allowed


def outbound_url_allowed(url: str) -> bool:
    """Return True if a URL is permitted by the optional tool net allowlist."""
    allowed = configured_net_allowlist()
    if not allowed:
        return capability_profile() != "private"
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    port = parsed.port
    hostport = f"{host}:{port}" if port else host
    for item in allowed:
        val = item.lower()
        if val == host or val == hostport:
            return True
        if val.startswith("*.") and host.endswith(val[1:]):
            return True
    return False


# Tools regular/public users must not execute directly. These either expose
# server/runtime access, sensitive user data, external messaging, persistent
# state changes, or generic loopback/integration surfaces.
NON_ADMIN_BLOCKED_TOOLS = {
    "bash",
    "python",
    "read_file",
    "write_file",
    "search_chats",
    "manage_memory",
    "manage_skills",
    "manage_tasks",
    "manage_endpoints",
    "manage_mcp",
    "manage_webhooks",
    "manage_tokens",
    "manage_documents",
    "manage_settings",
    "api_call",
    "app_api",
    "send_email",
    "reply_to_email",
    "list_emails",
    "read_email",
    "resolve_contact",
    "manage_contact",
    "manage_calendar",
    "vault_search",
    "vault_get",
    "vault_unlock",
    "download_model",
    "serve_model",
    "stop_served_model",
    "cancel_download",
    "adopt_served_model",
}


def is_public_blocked_tool(tool_name: Optional[str]) -> bool:
    """Return True when a non-admin/public user must not execute this tool."""
    if not tool_name:
        return False
    return tool_name in NON_ADMIN_BLOCKED_TOOLS or tool_name.startswith("mcp__")


def owner_is_admin_or_single_user(owner: Optional[str]) -> bool:
    """Return True for admins, or when auth is not configured yet."""
    try:
        from core.auth import AuthManager

        auth = AuthManager()
        if not auth.is_configured:
            return True
        return bool(owner and auth.is_admin(owner))
    except Exception as exc:
        logger.warning("Unable to evaluate owner admin status: %s", exc)
        return False


def blocked_tools_for_owner(owner: Optional[str]) -> Set[str]:
    """Tools to hide/disable for this owner under public-user policy."""
    blocked = profile_blocked_tools()
    if not owner_is_admin_or_single_user(owner):
        blocked.update(NON_ADMIN_BLOCKED_TOOLS)
    return blocked
