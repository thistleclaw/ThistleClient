"""Atomic private JSON files and consistent subscription selection."""
import json
import os
import tempfile


def write_json(path, data, *, indent=2):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    fd, temporary = tempfile.mkstemp(dir=directory, prefix=".thistle-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=indent)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def normalize_selection(data):
    subs = data.get("subs", {})
    if data.get("active_sub") not in subs:
        data["active_sub"] = next(iter(subs), "")
    nodes = subs.get(data["active_sub"], {}).get("nodes", [])
    if data.get("active_node") not in {node.get("tag") for node in nodes}:
        data["active_node"] = nodes[0].get("tag", "") if nodes else ""
