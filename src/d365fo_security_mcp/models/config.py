"""Configuration models for D365 F&O Security MCP Server."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class D365Profile(BaseSettings):
    """Connection profile for a D365 F&O environment.

    Values are read from environment variables with the D365FO_ prefix,
    or can be passed directly when creating the profile.
    """

    base_url: str = Field(
        description="D365 F&O environment URL, e.g. https://myenv.operations.dynamics.com",
        alias="D365FO_BASE_URL",
    )
    tenant_id: str = Field(
        description="Azure AD / Entra ID tenant ID",
        alias="D365FO_TENANT_ID",
    )
    client_id: str = Field(
        description="Azure AD application (client) ID",
        alias="D365FO_CLIENT_ID",
    )
    client_secret: str = Field(
        description="Azure AD application client secret",
        alias="D365FO_CLIENT_SECRET",
    )
    request_timeout: int = Field(
        default=60,
        description="HTTP request timeout in seconds",
    )
    request_delay_ms: int = Field(
        default=100,
        description="Pre-emptive delay between OData requests in milliseconds",
    )
    max_retries: int = Field(
        default=3,
        description="Maximum retries on HTTP 429 (throttling)",
    )

    model_config = {
        "env_prefix": "D365FO_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "populate_by_name": True,
    }

    @property
    def odata_url(self) -> str:
        """OData service root URL."""
        return f"{self.base_url.rstrip('/')}/data"

    @property
    def token_url(self) -> str:
        """Azure AD token endpoint."""
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

    @property
    def scope(self) -> str:
        """OAuth2 scope for D365 F&O."""
        return f"{self.base_url.rstrip('/')}/.default"


class ServerConfig(BaseSettings):
    """Server-level configuration for licence intelligence features."""

    licence_source: str = Field(
        default="assess-only",
        description="Licence data provider: assess-only, file, graph, ppac",
        alias="LICENCE_SOURCE",
    )
    licence_file_path: str = Field(
        default="",
        description="Path to licence CSV/JSON file (when licence_source=file)",
        alias="LICENCE_FILE_PATH",
    )
    currency: str = Field(
        default="GBP",
        description="ISO 4217 currency code for cost calculations",
        alias="CURRENCY",
    )
    batch_size: int = Field(
        default=50,
        description="Number of users to process per batch in full-environment scans",
    )
    graph_scope: str = Field(
        default="https://graph.microsoft.com/.default",
        description="OAuth2 scope for Microsoft Graph API",
        alias="D365FO_GRAPH_SCOPE",
    )
    stale_threshold_days: int = Field(
        default=7,
        description="Days after which licence source data is considered stale",
        alias="STALE_THRESHOLD_DAYS",
    )
    d365fo_version: str = Field(
        default="",
        description=(
            "D365 F&O application version override (e.g. '10.0.46'). Auto-detected if empty."
        ),
        alias="D365FO_VERSION",
    )
    sod_rules_file: str = Field(
        default="",
        description="Path to SoD conflict ruleset JSON file",
        alias="SOD_RULES_FILE",
    )
    app_insights_connection_string: str = Field(
        default="",
        description=(
            "Azure Application Insights connection string for login activity tracking. "
            "Enables D365 session detection via pageViews telemetry."
        ),
        alias="APP_INSIGHTS_CONNECTION_STRING",
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "populate_by_name": True,
    }
