"""Server configuration and licence-source registry introspection."""

from __future__ import annotations

import asyncio
import importlib.metadata
import logging
import os
import time
from typing import Any

from d365fo_security_mcp.models.config import D365Profile, ServerConfig
from d365fo_security_mcp.models.responses import ResponseMetadata, ToolResponse
from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.tools.providers.base import (
    BaseLicenceSourceProvider,
    LicenceSourceProvider,
)

logger = logging.getLogger(__name__)

# OData actions on DataManagementEntities that return version strings.
_VERSION_ACTIONS = [
    ("application", "GetApplicationVersion"),
    ("platform", "GetPlatformBuildVersion"),
    ("build", "GetApplicationBuildVersion"),
]


async def _detect_versions(
    client: ODataClient,
) -> dict[str, str | None]:
    """Detect D365 F&O versions via OData actions on DataManagementEntities.

    Calls three actions in parallel:

    - ``GetApplicationVersion`` → e.g. ``"10.0.46"``
    - ``GetPlatformBuildVersion`` → e.g. ``"7.0.7778.29"``
    - ``GetApplicationBuildVersion`` → e.g. ``"10.0.2428.63"``

    Returns a dict with keys ``application``, ``platform``, ``build``.
    Each value is the version string or ``None`` if the action failed.
    """

    async def _call(action_name: str) -> str | None:
        try:
            result = await asyncio.wait_for(
                client.call_action(action_name),
                timeout=5.0,
            )
            return result if result else None
        except Exception:
            logger.debug("Version action %s failed", action_name, exc_info=True)
            return None

    results = await asyncio.gather(*[_call(action) for _, action in _VERSION_ACTIONS])

    return {key: value for (key, _), value in zip(_VERSION_ACTIONS, results, strict=True)}


LICENCE_SOURCE_REGISTRY: dict[str, dict[str, Any]] = {
    "graph": {
        "description": "Read licence assignments from Microsoft Entra ID via Graph API",
        "required_params": ["D365FO_TENANT_ID", "D365FO_CLIENT_ID", "D365FO_CLIENT_SECRET"],
        "required_permissions": ["User.Read.All", "Directory.Read.All"],
        "note": None,
    },
    "ppac": {
        "description": "Read from Power Platform Admin Center licence report",
        "required_params": ["PPAC_ENVIRONMENT_ID", "PPAC_AUTH_TOKEN"],
        "required_permissions": None,
        "note": "PPAC provider is not yet implemented. Data refreshes every 72 hours.",
    },
    "file": {
        "description": "Read from a CSV/JSON file mapping users to assigned licence tiers",
        "required_params": ["LICENCE_FILE_PATH"],
        "required_permissions": None,
        "expected_columns": ["user_id", "assigned_tier"],
        "accepted_tiers": ["Enterprise", "Activity", "Universal", "None"],
        "note": "Quickest setup — export from PPAC or Entra and point to the file",
    },
}


def _check_env_status(required_params: list[str]) -> str:
    """Return 'configured', 'partially_configured', or 'not_configured'."""
    present = sum(1 for p in required_params if os.environ.get(p))
    if present == len(required_params):
        return "configured"
    if present > 0:
        return "partially_configured"
    return "not_configured"


def _build_available_sources(
    active_provider: str = "assess-only",
) -> dict[str, dict[str, Any]]:
    """Build the available sources dict with environment-presence status.

    Args:
        active_provider: Name of the currently active provider. Sources
            matching this name with credentials present get status ``"active"``
            instead of ``"configured"``.
    """
    sources: dict[str, dict[str, Any]] = {}
    for name, info in LICENCE_SOURCE_REGISTRY.items():
        env_status = _check_env_status(info["required_params"])
        # Promote "configured" → "active" when this source is the running provider
        status = "active" if name == active_provider and env_status == "configured" else env_status
        entry: dict[str, Any] = {
            "description": info["description"],
            "required_params": info["required_params"],
            "required_permissions": info.get("required_permissions"),
            "note": info.get("note"),
            "status": status,
        }
        if "expected_columns" in info:
            entry["expected_columns"] = info["expected_columns"]
        if "accepted_tiers" in info:
            entry["accepted_tiers"] = info["accepted_tiers"]
        sources[name] = entry
    return sources


async def get_security_server_config(
    client: ODataClient,
    server_config: ServerConfig,
    provider: LicenceSourceProvider,
    profile: D365Profile,
) -> ToolResponse:
    """Gather server configuration, environment info, and capabilities."""
    import time

    start = time.perf_counter()

    # Server version
    try:
        server_version = importlib.metadata.version("d365fo-security-mcp")
    except importlib.metadata.PackageNotFoundError:
        server_version = "unknown"

    # Environment connectivity check — use SecurityRoles (known entity) with $top=1
    connectivity = False
    try:
        rows = await asyncio.wait_for(
            client.query("SecurityRoles", select=["SecurityRoleIdentifier"], top=1),
            timeout=5.0,
        )
        connectivity = True
        _ = rows  # connectivity confirmed if query succeeded
    except Exception:
        connectivity = False

    # D365 version detection via OData actions (parallel).
    # Env var override applies to application version only.
    versions: dict[str, str | None] = {
        "application": None,
        "platform": None,
        "build": None,
    }
    if connectivity:
        try:
            versions = await _detect_versions(client)
        except Exception:
            logger.debug("Version detection failed", exc_info=True)

    # Env var override for application version
    if server_config.d365fo_version:
        versions["application"] = server_config.d365fo_version

    # Provider info
    prov_name = provider.provider_name()
    is_assess_only = prov_name == "assess-only"

    configured_source: str | None = None if is_assess_only else prov_name
    mode = "projection" if is_assess_only else "live"

    # Capabilities
    capabilities = {
        "assess_user_licence_requirements": True,
        "detect_over_licensed_users": True,
        "detect_under_licensed_users": not is_assess_only,
        "what_if_role_change": True,
        "get_role_licence_breakdown": True,
        "get_licence_summary_report": True,
        "get_security_server_config": True,
        "validate_licence_source": True,
    }

    # Limitations
    limitations: list[str] = []
    available_sources = _build_available_sources(active_provider=prov_name)
    if is_assess_only:
        limitations.append("detect_under_licensed_users unavailable — no licence source configured")
        limitations.append(
            "detect_over_licensed_users running in projection mode — "
            "savings data not meaningful without licence source"
        )
        # Check for credentials that are present but not activated
        for src_name, src_info in available_sources.items():
            if src_info["status"] == "configured":
                limitations.append(
                    f"{src_name.capitalize()} credentials detected but LICENCE_SOURCE is not set. "
                    f"Set LICENCE_SOURCE={src_name} to enable live licence detection."
                )

    duration_ms = int((time.perf_counter() - start) * 1000)

    result: dict[str, Any] = {
        "server_version": server_version,
        "environment": {
            "base_url": profile.base_url,
            "versions": versions,
            "connectivity": connectivity,
        },
        "licence_source": {
            "configured_source": configured_source,
            "mode": mode,
            "available_sources": available_sources,
        },
        "capabilities": capabilities,
        "limitations": limitations,
    }

    metadata = ResponseMetadata(
        provider=prov_name,
        environment=profile.base_url,
        duration_ms=duration_ms,
        currency=server_config.currency,
    )

    return ToolResponse(result=result, metadata=metadata)


async def validate_licence_source(
    provider: LicenceSourceProvider,
    server_config: ServerConfig,
    source: str = "",
) -> ToolResponse:
    """Validate a licence source and return structured diagnostics.

    Args:
        provider: The currently configured licence source provider.
        server_config: Server configuration.
        source: Optional override to validate a specific source instead of
            the currently configured one. E.g. "graph", "file".

    Returns:
        ToolResponse with validation result including authentication status,
        permissions, data statistics, and remediation guidance on failure.
    """
    from d365fo_security_mcp.tools.providers import create_provider

    start = time.perf_counter()

    effective_provider = provider

    # If source override is provided and differs from current provider, create temporary
    if source and source != provider.provider_name():
        kwargs: dict[str, Any] = {}
        if source == "file":
            kwargs["file_path"] = os.environ.get("LICENCE_FILE_PATH", "")
        elif source == "graph":
            kwargs["tenant_id"] = os.environ.get("D365FO_TENANT_ID", "")
            kwargs["client_id"] = os.environ.get("D365FO_CLIENT_ID", "")
            kwargs["client_secret"] = os.environ.get("D365FO_CLIENT_SECRET", "")
        try:
            effective_provider = create_provider(source, **kwargs)
        except (ValueError, KeyError) as exc:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return ToolResponse(
                result={
                    "source": source,
                    "status": "error",
                    "validation": None,
                    "error": str(exc),
                },
                metadata=ResponseMetadata(
                    provider=source,
                    duration_ms=duration_ms,
                    currency=server_config.currency,
                ),
            )

    prov_name = effective_provider.provider_name()

    # If assess-only, return not_configured guidance
    if prov_name == "assess-only":
        duration_ms = int((time.perf_counter() - start) * 1000)
        return ToolResponse(
            result={
                "source": "assess-only",
                "status": "not_configured",
                "validation": None,
                "error": (
                    "No external licence source configured. "
                    "Call get_security_server_config for available options "
                    "and setup guidance."
                ),
            },
            metadata=ResponseMetadata(
                provider=prov_name,
                duration_ms=duration_ms,
                currency=server_config.currency,
            ),
        )

    # Call validate() on the effective provider
    if isinstance(effective_provider, BaseLicenceSourceProvider):
        validation_result = await effective_provider.validate()
    else:
        validation_result = {"status": "not_supported"}

    # Add activation hint when validating a source that isn't the active provider
    active_name = provider.provider_name()
    is_non_active = prov_name != active_name or active_name == "assess-only"
    is_success = (
        isinstance(validation_result, dict) and validation_result.get("status") == "connected"
    )
    if is_non_active and is_success:
        validation_result["activation_hint"] = (
            f"Source validated successfully but is not the active licence source. "
            f"Set LICENCE_SOURCE={prov_name} in your environment to activate it "
            f"for detection tools."
        )

    duration_ms = int((time.perf_counter() - start) * 1000)

    return ToolResponse(
        result=validation_result,
        metadata=ResponseMetadata(
            provider=prov_name,
            duration_ms=duration_ms,
            currency=server_config.currency,
        ),
    )
