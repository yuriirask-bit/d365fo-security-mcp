from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx
import msal

from d365fo_security_mcp.tools.providers.base import BaseLicenceSourceProvider

logger = logging.getLogger(__name__)

# Tier priority order for resolving highest tier when a user has multiple SKUs.
# Higher index = higher priority tier.
_TIER_PRIORITY: list[str] = ["Universal", "Activity", "Enterprise"]

# Mapping from Microsoft 365 SKU product GUIDs to D365 licence tier names.
_SKU_TO_TIER: dict[str, str] = {
    "6fd2c87f-b296-42f0-b197-1e91e994b900": "Enterprise",  # Dynamics 365 Finance
    "ea126fc5-a19e-42e2-a731-da9d437bffcf": "Enterprise",  # Dynamics 365 SCM
    "f30db892-07e9-47e9-837c-80727f46fd3d": "Activity",  # Dynamics 365 Activity
    "ccba3cfe-71ef-423a-bd87-b6df3dce59a9": "Universal",  # Dynamics 365 Team Members
    "a403ee9-54f0-4239-a931-be1bc1158a30": "Enterprise",  # Dynamics 365 Unified Operations
}

_GRAPH_USERS_URL = (
    "https://graph.microsoft.com/v1.0/users"
    "?$select=id,displayName,userPrincipalName,mail,mailNickname,assignedLicenses"
)


def _higher_tier(current: str | None, candidate: str) -> str:
    """Return whichever tier has higher priority."""
    if current is None:
        return candidate
    current_rank = _TIER_PRIORITY.index(current) if current in _TIER_PRIORITY else -1
    candidate_rank = _TIER_PRIORITY.index(candidate) if candidate in _TIER_PRIORITY else -1
    return candidate if candidate_rank > current_rank else current


class GraphProvider(BaseLicenceSourceProvider):
    """Licence source provider that fetches assigned licences from Microsoft Graph."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        graph_scope: str = "https://graph.microsoft.com/.default",
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._graph_scope = graph_scope
        self._warnings: list[str] = []

    @property
    def warnings(self) -> list[str]:
        return self._warnings

    def _acquire_token(self) -> str:
        """Acquire an OAuth2 access token via MSAL client-credentials flow."""
        authority = f"https://login.microsoftonline.com/{self._tenant_id}"
        app = msal.ConfidentialClientApplication(
            self._client_id,
            authority=authority,
            client_credential=self._client_secret,
        )
        result = app.acquire_token_for_client(scopes=[self._graph_scope])
        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "unknown"))
            logger.error("Graph token acquisition failed: %s", error)
            raise RuntimeError(
                "Failed to acquire Graph API token. "
                "Verify D365FO_TENANT_ID, D365FO_CLIENT_ID, and "
                "D365FO_CLIENT_SECRET are correct and the app registration "
                "has the required permissions."
            )
        return result["access_token"]

    async def get_assigned_licences(self) -> dict[str, str]:
        """Fetch all Graph users and return a mapping of user key → highest D365 tier.

        Builds a multi-key lookup so that D365 users can be matched by any of:
        Entra ID object ID, userPrincipalName, mail, mailNickname, or UPN
        local part (the portion before ``@``).  All keys are lowercased for
        case-insensitive matching.

        Pages through all results using ``@odata.nextLink``. SKU GUIDs that
        are not in the known mapping are logged as warnings and excluded.
        """
        self._warnings = []

        token = self._acquire_token()
        headers = {"Authorization": f"Bearer {token}"}

        result: dict[str, str] = {}

        async with httpx.AsyncClient() as client:
            url: str | None = _GRAPH_USERS_URL
            while url:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()

                for user in data.get("value", []):
                    entra_id: str = user.get("id", "")
                    if not entra_id:
                        continue

                    highest_tier: str | None = None
                    for assigned in user.get("assignedLicenses", []):
                        sku_id: str = assigned.get("skuId", "")
                        tier = _SKU_TO_TIER.get(sku_id)
                        if tier is None:
                            if sku_id:
                                display = user.get("displayName") or entra_id
                                warn_msg = (
                                    f"Unknown SKU GUID '{sku_id}' for user "
                                    f"'{display}' — excluded from licence mapping"
                                )
                                logger.warning(warn_msg)
                                self._warnings.append(warn_msg)
                        else:
                            highest_tier = _higher_tier(highest_tier, tier)

                    if highest_tier is None:
                        continue

                    # Register tier under every available identifier (lowercased).
                    keys: list[str] = [entra_id.lower()]
                    upn: str = user.get("userPrincipalName") or ""
                    mail: str = user.get("mail") or ""
                    nickname: str = user.get("mailNickname") or ""

                    if upn:
                        keys.append(upn.lower())
                        local_part = upn.split("@")[0].lower()
                        if local_part:
                            keys.append(local_part)
                    if mail:
                        keys.append(mail.lower())
                        mail_local = mail.split("@")[0].lower()
                        if mail_local and mail_local not in keys:
                            keys.append(mail_local)
                    if nickname:
                        keys.append(nickname.lower())

                    for key in dict.fromkeys(keys):  # dedupe, preserve order
                        if key not in result:
                            result[key] = highest_tier

                url = data.get("@odata.nextLink")

        return result

    def provider_name(self) -> str:
        return "graph"

    async def validate(self) -> dict[str, Any]:
        """Validate the Graph licence source.

        Tests authentication, permissions, counts users with/without
        assignments, collects licence tiers found, and sets last_sync_time.
        """
        validation: dict[str, Any] = {
            "authentication": "failed",
            "permissions": None,
            "missing_permissions": None,
            "data_available": False,
            "users_with_assignments": 0,
            "users_without_assignments": 0,
            "licence_tiers_found": [],
            "last_sync": None,
            "remediation": None,
        }

        # Step 1: Test authentication
        try:
            token = self._acquire_token()
        except Exception as exc:
            logger.error("Graph validation auth failed: %s", exc)
            validation["remediation"] = (
                "Authentication failed. "
                "Verify that D365FO_TENANT_ID, D365FO_CLIENT_ID, and "
                "D365FO_CLIENT_SECRET are correct and that the app registration "
                "has not expired."
            )
            return {
                "source": "graph",
                "status": "error",
                "validation": validation,
            }

        validation["authentication"] = "ok"

        # Step 2: Test permissions with a small Graph API call
        headers = {"Authorization": f"Bearer {token}"}
        try:
            async with httpx.AsyncClient() as client:
                test_url = (
                    "https://graph.microsoft.com/v1.0/users"
                    "?$select=id,displayName,userPrincipalName,mail,"
                    "mailNickname,assignedLicenses&$top=100"
                )
                response = await client.get(test_url, headers=headers)

                if response.status_code == 403:
                    validation["permissions"] = "insufficient"
                    validation["missing_permissions"] = ["Directory.Read.All"]
                    validation["remediation"] = (
                        "The application lacks required permissions. "
                        "Grant Directory.Read.All (Application) to the app "
                        "registration in Azure Portal > App registrations > "
                        "API permissions, then grant admin consent."
                    )
                    return {
                        "source": "graph",
                        "status": "error",
                        "validation": validation,
                    }

                response.raise_for_status()
                data = response.json()

        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 403:
                validation["permissions"] = "insufficient"
                validation["missing_permissions"] = ["Directory.Read.All"]
                validation["remediation"] = (
                    "The application lacks required permissions. "
                    "Grant Directory.Read.All (Application) to the app "
                    "registration in Azure Portal > App registrations > "
                    "API permissions, then grant admin consent."
                )
            else:
                validation["remediation"] = (
                    f"Graph API request failed with status {exc.response.status_code}: "
                    f"{exc.response.text}"
                )
            return {
                "source": "graph",
                "status": "error",
                "validation": validation,
            }
        except Exception as exc:
            validation["remediation"] = f"Graph API request failed: {exc}"
            return {
                "source": "graph",
                "status": "error",
                "validation": validation,
            }

        validation["permissions"] = "ok"

        # Step 3: Count users and collect tiers
        users_with = 0
        users_without = 0
        tiers_found: set[str] = set()

        for user in data.get("value", []):
            assigned_licenses = user.get("assignedLicenses", [])
            has_d365_licence = False
            for assigned in assigned_licenses:
                sku_id = assigned.get("skuId", "")
                tier = _SKU_TO_TIER.get(sku_id)
                if tier is not None:
                    has_d365_licence = True
                    tiers_found.add(tier)
            if has_d365_licence:
                users_with += 1
            else:
                users_without += 1

        now = datetime.now(timezone.utc)
        self._last_sync_time = now

        validation["data_available"] = True
        validation["users_with_assignments"] = users_with
        validation["users_without_assignments"] = users_without
        validation["licence_tiers_found"] = sorted(tiers_found)
        validation["last_sync"] = now.isoformat()

        return {
            "source": "graph",
            "status": "connected",
            "validation": validation,
        }
