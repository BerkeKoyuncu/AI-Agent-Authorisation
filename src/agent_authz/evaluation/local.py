"""Read-only loopback inspection and resource checks for the local runner."""

import ctypes
from ctypes import wintypes
from http.client import HTTPConnection, HTTPException
import json
from pathlib import Path
import sys

from .manifest import COLD_RAM_FLOOR, CONTEXT_LENGTH, MODEL_DIGEST, MODEL_TAG, OLLAMA_VERSION, WARM_RAM_FLOOR


class LocalBlocked(RuntimeError):
    """A trusted preflight gate could not be confirmed."""


def available_memory() -> int | None:
    if sys.platform == "win32":
        class Memory(ctypes.Structure):
            _fields_ = [("length", wintypes.DWORD), ("load", wintypes.DWORD)] + [
                (field, ctypes.c_ulonglong) for field in (
                    "total", "available", "page_total", "page_available",
                    "virtual_total", "virtual_available", "extended_available",
                )
            ]

        state = Memory(ctypes.sizeof(Memory))
        if ctypes.WinDLL("kernel32.dll").GlobalMemoryStatusEx(ctypes.byref(state)):
            return state.available
    if sys.platform.startswith("linux"):
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    return None


def _local_json(endpoint: str) -> dict:
    connection = HTTPConnection("127.0.0.1", 11434, timeout=5)
    try:
        connection.request("GET", endpoint)
        response = connection.getresponse()
        body = response.read(1_048_577)
        if response.status != 200 or len(body) > 1_048_576:
            raise LocalBlocked("Unexpected local metadata response.")
        result = json.loads(body)
        if type(result) is not dict:
            raise LocalBlocked("Invalid local metadata.")
        return result
    except (OSError, ValueError, HTTPException) as error:
        raise LocalBlocked("Local metadata unavailable.") from error
    finally:
        connection.close()


def inspect_local(*, require_headroom: bool = True) -> dict:
    version = _local_json("/api/version").get("version")
    if version != OLLAMA_VERSION:
        raise LocalBlocked("Ollama version differs from the manifest.")
    roster = _local_json("/api/tags").get("models")
    if type(roster) is not list:
        raise LocalBlocked("Invalid installed-model list.")
    selected = next((row for row in roster if type(row) is dict and row.get("model", row.get("name")) == MODEL_TAG), None)
    details = selected.get("details") if selected is not None else None
    if (selected is None or selected.get("digest") != MODEL_DIGEST
            or selected.get("remote_host") or selected.get("remote_model")
            or type(selected.get("size")) is not int or selected["size"] <= 0
            or type(details) is not dict or details.get("format") != "gguf"
            or details.get("quantization_level") != "Q4_K_M"):
        raise LocalBlocked("Expected local model metadata unavailable or changed.")
    running = _local_json("/api/ps").get("models")
    if type(running) is not list:
        raise LocalBlocked("Invalid runner inventory.")
    loaded = next((row for row in running if type(row) is dict and row.get("model", row.get("name")) == MODEL_TAG), None)
    if loaded and (loaded.get("digest") != MODEL_DIGEST or loaded.get("context_length") != CONTEXT_LENGTH
                   or loaded.get("size_vram") != 0):
        raise LocalBlocked("Loaded runner differs from the pinned CPU and context configuration.")
    memory = available_memory()
    floor = WARM_RAM_FLOOR if loaded else COLD_RAM_FLOOR
    if require_headroom and (memory is None or memory < floor):
        raise LocalBlocked(f"Available RAM below launch floor ({memory} bytes available; {floor} required).")
    return {"version": version, "model_state": "warm" if loaded else "cold", "context_length":
            loaded.get("context_length") if loaded else None, "loaded_bytes": loaded.get("size") if loaded else None,
            "vram_bytes": loaded.get("size_vram") if loaded else None, "available_memory_bytes": memory}
