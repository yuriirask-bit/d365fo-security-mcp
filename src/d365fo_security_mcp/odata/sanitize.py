"""Input sanitization utilities for OData queries."""

from __future__ import annotations

import re


def escape_odata_string(value: str) -> str:
    """Escape a string value for safe use in OData filter expressions.

    OData string literals are delimited by single quotes.  A literal
    single quote inside the string must be doubled (``''``).  This
    function also rejects characters that could alter query semantics.

    Raises ``ValueError`` if *value* contains control characters or
    newlines (never valid in an OData identifier/filter value).
    """
    if re.search(r"[\x00-\x1f\x7f]", value):
        raise ValueError("OData filter value contains invalid control characters")
    return value.replace("'", "''")
