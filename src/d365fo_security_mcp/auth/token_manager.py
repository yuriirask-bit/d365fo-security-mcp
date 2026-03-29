from __future__ import annotations

import logging

import msal

from d365fo_security_mcp.models.config import D365Profile

logger = logging.getLogger(__name__)


class TokenManager:
    def __init__(self, profile: D365Profile) -> None:
        self._profile = profile
        self._app: msal.ConfidentialClientApplication | None = None

    def _get_app(self) -> msal.ConfidentialClientApplication:
        if self._app is None:
            authority = f"https://login.microsoftonline.com/{self._profile.tenant_id}"
            self._app = msal.ConfidentialClientApplication(
                client_id=self._profile.client_id,
                client_credential=self._profile.client_secret,
                authority=authority,
            )
        return self._app

    def get_access_token(self) -> str:
        app = self._get_app()
        scopes = [self._profile.scope]

        result = app.acquire_token_silent(scopes=scopes, account=None)
        if result and "access_token" in result:
            logger.debug("Access token retrieved from cache.")
            return result["access_token"]

        logger.debug("No cached token found; acquiring fresh token from identity provider.")
        result = app.acquire_token_for_client(scopes=scopes)

        if result and "access_token" in result:
            return result["access_token"]

        error_description = (result or {}).get(
            "error_description", "Unknown error acquiring token."
        )
        raise RuntimeError(error_description)
