from __future__ import annotations

from d365fo_security_mcp.tools.providers.assess_only import AssessOnlyProvider
from d365fo_security_mcp.tools.providers.base import LicenceSourceProvider
from d365fo_security_mcp.tools.providers.file_provider import FileProvider
from d365fo_security_mcp.tools.providers.graph_provider import GraphProvider
from d365fo_security_mcp.tools.providers.ppac_provider import PpacProvider

__all__ = [
    "LicenceSourceProvider",
    "AssessOnlyProvider",
    "FileProvider",
    "GraphProvider",
    "PpacProvider",
    "create_provider",
]


def create_provider(licence_source: str, **kwargs) -> LicenceSourceProvider:
    """Factory that returns the appropriate LicenceSourceProvider.

    Args:
        licence_source: One of "assess-only", "file", "graph", or "ppac".
        **kwargs: Additional keyword arguments forwarded to the selected provider:
            - file:  file_path (str)
            - graph: tenant_id (str), client_id (str), client_secret (str)

    Returns:
        A concrete LicenceSourceProvider instance.

    Raises:
        ValueError: If licence_source is not a recognised option.
        KeyError:   If a required kwarg for the selected provider is absent.
    """
    if licence_source == "assess-only":
        return AssessOnlyProvider()
    elif licence_source == "file":
        return FileProvider(file_path=kwargs["file_path"])
    elif licence_source == "graph":
        return GraphProvider(
            tenant_id=kwargs["tenant_id"],
            client_id=kwargs["client_id"],
            client_secret=kwargs["client_secret"],
        )
    elif licence_source == "ppac":
        return PpacProvider()
    else:
        raise ValueError(
            f"Unsupported licence_source '{licence_source}'. "
            "Supported options are: 'assess-only', 'file', 'graph', 'ppac'."
        )
