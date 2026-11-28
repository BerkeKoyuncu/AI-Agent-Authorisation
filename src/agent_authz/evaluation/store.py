"""Local single-writer trial storage with crash markers and an immutable manifest."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile

from .manifest import Manifest, load_manifest


def atomic_text(path: Path, text: str) -> None:
    with tempfile.NamedTemporaryFile("w", dir=path.parent, encoding="utf-8", newline="\n", delete=False) as handle:
        name = Path(handle.name)
        try:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            handle.close()
            name.unlink(missing_ok=True)
            raise
    try:
        os.replace(name, path)
    finally:
        name.unlink(missing_ok=True)


def write_json(path: Path, value: object) -> None:
    atomic_text(path, json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False) + "\n")


@contextmanager
def writer_lock(root: Path):
    with (root / ".writer.lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt

            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def initialise(root: Path, manifest: Manifest) -> None:
    root.mkdir(parents=True, exist_ok=True)
    with writer_lock(root):
        path = root / "experiment-manifest.json"
        if path.exists():
            if load_manifest(path) != manifest:
                raise ValueError("Output directory already belongs to a different manifest.")
            return
        if any(item.name != ".writer.lock" for item in root.iterdir()):
            raise ValueError("Use a new or empty experiment directory.")
        atomic_text(path, manifest.serialise())


def read_results(root: Path, manifest: Manifest) -> list[dict]:
    rows = []
    for trial in manifest.trials:
        path = root / "trials" / trial.trial_id / "result.json"
        if path.exists():
            row = json.loads(path.read_text(encoding="utf-8"))
            if row.get("trial_id") != trial.trial_id or row.get("experiment_id") != manifest.experiment_id:
                raise ValueError("Stored result does not belong to the frozen trial.")
            rows.append(row)
    return rows
