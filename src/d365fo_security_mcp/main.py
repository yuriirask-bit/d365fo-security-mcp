from __future__ import annotations

import logging
import os
from pathlib import Path

# When a .env file exists in the working directory, it is the canonical source
# for LICENCE_SOURCE.  Remove any value injected by the host process so that
# pydantic-settings reads from .env instead of from a potentially stale
# process environment.  When no .env is present (e.g. Claude Desktop),
# the host-provided env var is kept as-is.
if Path(".env").is_file():
    os.environ.pop("LICENCE_SOURCE", None)

from d365fo_security_mcp.server import mcp


def main() -> None:
    """Configure logging and start the MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    mcp.run()


if __name__ == "__main__":
    main()
