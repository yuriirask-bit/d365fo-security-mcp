from __future__ import annotations

import contextlib
import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from d365fo_security_mcp.tools.providers.base import BaseLicenceSourceProvider

logger = logging.getLogger(__name__)

VALID_TIER_NAMES = frozenset(
    {
        "None",
        "SelfServe",
        "Task",
        "Functional",
        "Enterprise",
        "Server",
        "Universal",
        "Activity",
        "Finance",
        "SCM",
        "Commerce",
        "Project",
        "HR",
        "Operations",
    }
)


_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


class FileProvider(BaseLicenceSourceProvider):
    def __init__(self, file_path: str) -> None:
        path = Path(file_path).resolve()

        # Validate extension
        if path.suffix.lower() not in {".json", ".csv"}:
            raise ValueError(f"Licence file must be .json or .csv, got: {path.suffix}")

        self._file_path = path
        self._warnings: list[str] = []

    @property
    def warnings(self) -> list[str]:
        return self._warnings

    def get_warnings(self) -> list[str]:
        return self._warnings

    async def get_assigned_licences(self) -> dict[str, str]:
        self._warnings = []

        if not self._file_path.exists():
            raise FileNotFoundError(f"Licence file not found: {self._file_path}")

        # Guard against excessively large files
        file_size = self._file_path.stat().st_size
        if file_size > _MAX_FILE_SIZE:
            raise ValueError(
                f"Licence file exceeds {_MAX_FILE_SIZE // (1024 * 1024)} MB "
                f"size limit ({file_size} bytes)."
            )

        suffix = self._file_path.suffix.lower()

        if suffix == ".json":
            return self._load_json()
        elif suffix == ".csv":
            return self._load_csv()
        else:
            raise ValueError(f"Unsupported file extension '{suffix}'. Expected .json or .csv.")

    def _load_json(self) -> dict[str, str]:
        result: dict[str, str] = {}

        with self._file_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        if isinstance(data, dict):
            for row_num, (key, value) in enumerate(data.items(), start=1):
                if not isinstance(key, str) or not isinstance(value, str):
                    self._warnings.append(
                        f"Row {row_num}: skipped — key and value must both be strings "
                        f"(got key={type(key).__name__}, value={type(value).__name__})"
                    )
                    continue
                if value not in VALID_TIER_NAMES:
                    self._warnings.append(
                        f"Row {row_num}: skipped — unrecognised tier name '{value}'"
                    )
                    continue
                result[key] = value
        elif isinstance(data, list):
            for row_num, entry in enumerate(data, start=1):
                if not isinstance(entry, dict):
                    self._warnings.append(
                        f"Row {row_num}: skipped — expected an object, got {type(entry).__name__}"
                    )
                    continue
                user_id = entry.get("user_id")
                licence = entry.get("licence")
                if not isinstance(user_id, str) or not user_id:
                    self._warnings.append(
                        f"Row {row_num}: skipped — missing or invalid 'user_id' field"
                    )
                    continue
                if not isinstance(licence, str) or not licence:
                    self._warnings.append(
                        f"Row {row_num}: skipped — missing or invalid 'licence' field"
                    )
                    continue
                if licence not in VALID_TIER_NAMES:
                    self._warnings.append(
                        f"Row {row_num}: skipped — unrecognised tier name '{licence}'"
                    )
                    continue
                result[user_id] = licence
        else:
            raise ValueError(
                "JSON file must contain either a list of objects or a dict mapping "
                "user_id to licence."
            )

        return result

    def _load_csv(self) -> dict[str, str]:
        result: dict[str, str] = {}

        with self._file_path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            fieldnames = reader.fieldnames or []
            if "user_id" not in fieldnames:
                raise ValueError("CSV file must contain a 'user_id' column")
            if "licence" not in fieldnames:
                raise ValueError("CSV file must contain a 'licence' column")

            for row_num, row in enumerate(reader, start=2):  # row 1 is the header
                user_id = row.get("user_id", "").strip()
                licence = row.get("licence", "").strip()

                if not user_id:
                    self._warnings.append(
                        f"Row {row_num}: skipped — missing or empty 'user_id' column"
                    )
                    continue
                if not licence:
                    self._warnings.append(
                        f"Row {row_num}: skipped — missing or empty 'licence' column"
                    )
                    continue
                if licence not in VALID_TIER_NAMES:
                    self._warnings.append(
                        f"Row {row_num}: skipped — unrecognised tier name '{licence}'"
                    )
                    continue

                result[user_id] = licence

        return result

    def provider_name(self) -> str:
        return "file"

    async def validate(self) -> dict[str, Any]:
        """Validate the file licence source.

        Checks file existence, readability, parses content, counts rows,
        collects errors and licence tiers found, and records last modified time.
        """
        validation: dict[str, Any] = {
            "file_path": str(self._file_path),
            "file_exists": False,
            "file_readable": False,
            "rows_parsed": 0,
            "rows_with_errors": 0,
            "errors": [],
            "licence_tiers_found": [],
            "last_modified": None,
        }

        # Check existence
        if not self._file_path.exists():
            return {
                "source": "file",
                "status": "error",
                "validation": validation,
            }

        validation["file_exists"] = True

        # Check readability
        try:
            with self._file_path.open("r", encoding="utf-8") as fh:
                fh.read(1)
        except OSError:
            return {
                "source": "file",
                "status": "error",
                "validation": validation,
            }

        validation["file_readable"] = True

        # Record last_modified
        mtime = self._file_path.stat().st_mtime
        last_modified_dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        validation["last_modified"] = last_modified_dt.isoformat()
        self._last_sync_time = last_modified_dt

        # Parse the file and collect statistics
        try:
            result = await self.get_assigned_licences()
            rows_parsed = len(result)
            warnings = self._warnings

            errors: list[dict[str, Any]] = []
            for warning in warnings:
                # Extract row number from warning format "Row N: ..."
                row_num: int | None = None
                if warning.startswith("Row "):
                    with contextlib.suppress(IndexError, ValueError):
                        row_num = int(warning.split(":")[0].split(" ")[1])
                errors.append({"row": row_num, "issue": warning})

            tiers_found = sorted(set(result.values()))

            validation["rows_parsed"] = rows_parsed
            validation["rows_with_errors"] = len(errors)
            validation["errors"] = errors
            validation["licence_tiers_found"] = tiers_found

        except (ValueError, json.JSONDecodeError) as exc:
            validation["errors"] = [{"row": None, "issue": str(exc)}]
            validation["rows_with_errors"] = 1

        return {
            "source": "file",
            "status": "connected",
            "validation": validation,
        }
