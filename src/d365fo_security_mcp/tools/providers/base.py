from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class LicenceSourceProvider(Protocol):
    async def get_assigned_licences(self) -> dict[str, str]:
        """Return a mapping of user_id to licence tier name."""
        ...

    def provider_name(self) -> str:
        """Return the name of this provider."""
        ...


class BaseLicenceSourceProvider:
    """Concrete base class providing default validate() and last_sync_time.

    Providers inherit from this to get default implementations while still
    satisfying the LicenceSourceProvider Protocol via structural typing.
    """

    _last_sync_time: datetime | None = None

    @property
    def last_sync_time(self) -> datetime | None:
        """Timestamp of last successful data retrieval."""
        return self._last_sync_time

    async def validate(self) -> dict[str, Any]:
        """Test connectivity and return validation statistics.

        Subclasses override with source-specific validation logic.
        """
        return {"status": "not_supported"}
