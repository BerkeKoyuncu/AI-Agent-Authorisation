"""Append only the gateway's approved event fields to a trusted local file."""

import json
import os
from pathlib import Path

from ..audit.schema import validate_event


class JsonlAudit:
    def __init__(self, path: Path) -> None:
        self._path = path.resolve()

    def __call__(self, event: dict[str, object]) -> None:
        line = json.dumps(dict(validate_event(event)), ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        with self._path.open("a", encoding="utf-8", newline="\n") as journal:
            journal.write(line + "\n")
            journal.flush()
            os.fsync(journal.fileno())
