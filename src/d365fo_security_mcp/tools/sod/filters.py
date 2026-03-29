"""Centralised service account filter using Provider-based native detection.

Queries the Admin user's Provider field as the native baseline. Users whose
Provider differs from Admin's are classified as non-native (guests or
service/system accounts) and can be excluded from reports.
"""

from __future__ import annotations

import logging
from typing import Any

from d365fo_security_mcp.odata.client import ODataClient
from d365fo_security_mcp.odata.sanitize import escape_odata_string
from d365fo_security_mcp.tools.constants import ADMIN_USER_ID, ENTITY_SYSTEM_USERS

logger = logging.getLogger(__name__)


async def get_native_provider(client: ODataClient) -> tuple[str, list[str]]:
    """Look up the Admin user's Provider value as the native baseline.

    Returns:
        Tuple of (native_provider, warnings). If Admin is not found or has
        no Provider, returns ("", [warning_message]).
    """
    warnings: list[str] = []
    try:
        admin_data = await client.query(
            ENTITY_SYSTEM_USERS,
            filter_expr=f"UserID eq '{escape_odata_string(ADMIN_USER_ID)}'",
            select=["UserID", "NetworkDomain"],
        )
    except (RuntimeError, OSError):
        logger.debug("Provider field query failed, trying without select")
        admin_data = await client.query(
            ENTITY_SYSTEM_USERS,
            filter_expr=f"UserID eq '{escape_odata_string(ADMIN_USER_ID)}'",
        )

    if not admin_data:
        warnings.append(
            f"Admin user '{ADMIN_USER_ID}' not found. Service account filtering unavailable."
        )
        return "", warnings

    # Try NetworkDomain as the provider field (Provider is not on SystemUsers)
    provider = admin_data[0].get("NetworkDomain", "")
    if not provider:
        warnings.append(
            "Admin user has no NetworkDomain value. Service account filtering unavailable."
        )
        return "", warnings

    return provider, warnings


def is_native_user(user: dict[str, Any], native_provider: str) -> bool:
    """Check if a user's Provider matches the native baseline."""
    if not native_provider:
        return True  # No baseline → treat all as native (no filtering)
    return user.get("NetworkDomain", "") == native_provider


def filter_non_native_users(
    users: list[dict[str, Any]],
    native_provider: str,
) -> tuple[list[dict[str, Any]], int]:
    """Filter out non-native users and return the count of excluded accounts.

    Returns:
        Tuple of (filtered_users, excluded_count).
    """
    if not native_provider:
        return users, 0

    filtered = [u for u in users if is_native_user(u, native_provider)]
    excluded = len(users) - len(filtered)
    return filtered, excluded
