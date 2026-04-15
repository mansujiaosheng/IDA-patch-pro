"""Persisted search history and result snapshots for the assembly search dialog."""

import time

from ..ida_adapter import current_database_identity, current_database_label
from .history_store import load_plugin_settings, save_plugin_settings

SEARCH_HISTORY_KEY = "assembly_search_history"
SEARCH_HISTORY_LIMIT = 30
SEARCH_RESULT_LIMIT = 200


def _normalize_search_result_row(row):
    """Normalize one persisted or live search-result row."""
    if not isinstance(row, dict):
        return None
    try:
        ea = int(row.get("ea"))
        size = int(row.get("size", 0))
    except Exception:
        return None

    raw_bytes = row.get("bytes", b"")
    if isinstance(raw_bytes, str):
        try:
            raw_bytes = bytes.fromhex(raw_bytes)
        except ValueError:
            raw_bytes = b""
    else:
        raw_bytes = bytes(raw_bytes or b"")

    notes = row.get("notes") or []
    if not isinstance(notes, list):
        notes = [str(notes)]

    return {
        "ea": ea,
        "size": size,
        "bytes": raw_bytes,
        "notes": [str(note) for note in notes if note is not None],
        "disasm_text": str(row.get("disasm_text") or ""),
    }


def _serialize_search_result(result):
    """Convert one live search-result dict into a compact persisted snapshot."""
    if not isinstance(result, dict):
        return None
    rows = []
    for row in (result.get("results") or [])[:SEARCH_RESULT_LIMIT]:
        normalized = _normalize_search_result_row(row)
        if normalized is None:
            continue
        rows.append(
            {
                "ea": normalized["ea"],
                "size": normalized["size"],
                "bytes_hex": normalized["bytes"].hex(),
                "notes": list(normalized["notes"]),
                "disasm_text": normalized["disasm_text"],
            }
        )

    return {
        "start_ea": int(result.get("start_ea", 0) or 0),
        "end_ea": int(result.get("end_ea", 0) or 0),
        "scanned_count": int(result.get("scanned_count", 0) or 0),
        "result_count": int(result.get("result_count", len(rows)) or 0),
        "max_results": int(result.get("max_results", len(rows) or 1) or 1),
        "results": rows,
    }


def _deserialize_search_result(snapshot, query_text="", mode="exact"):
    """Convert one persisted snapshot back into dialog/search-result shape."""
    if not isinstance(snapshot, dict):
        return None
    rows = []
    for row in snapshot.get("results") or []:
        normalized = _normalize_search_result_row(
            {
                "ea": row.get("ea"),
                "size": row.get("size"),
                "bytes": row.get("bytes_hex", ""),
                "notes": row.get("notes") or [],
                "disasm_text": row.get("disasm_text") or "",
            }
        )
        if normalized is None:
            continue
        rows.append(normalized)
    return {
        "query_text": query_text,
        "search_mode": mode,
        "start_ea": int(snapshot.get("start_ea", 0) or 0),
        "end_ea": int(snapshot.get("end_ea", 0) or 0),
        "scanned_count": int(snapshot.get("scanned_count", 0) or 0),
        "results": rows,
        "result_count": int(snapshot.get("result_count", len(rows)) or 0),
        "max_results": int(snapshot.get("max_results", len(rows) or 1) or 1),
    }


def normalize_search_history_entry(entry):
    """Normalize one persisted search-history entry."""
    if isinstance(entry, str):
        entry = {"query_text": entry, "mode": "exact"}
    if not isinstance(entry, dict):
        return None

    query_text = "\n".join(line.rstrip() for line in str(entry.get("query_text") or "").splitlines()).strip()
    if not query_text:
        return None

    mode = str(entry.get("mode") or "exact").strip().lower()
    if mode not in ("exact", "text"):
        mode = "exact"

    snapshot = _serialize_search_result(entry.get("search_result")) if entry.get("search_result") else None
    if snapshot is None and entry.get("search_snapshot"):
        snapshot = entry.get("search_snapshot")
    restored_result = _deserialize_search_result(snapshot, query_text=query_text, mode=mode)

    return {
        "query_text": query_text,
        "mode": mode,
        "created_at": float(entry.get("created_at") or time.time()),
        "project_key": str(entry.get("project_key") or ""),
        "project_label": str(entry.get("project_label") or ""),
        "search_result": restored_result,
        "search_snapshot": snapshot if isinstance(snapshot, dict) else None,
    }


def load_search_history(limit=SEARCH_HISTORY_LIMIT, project_key=None):
    """Load recent assembly-search history entries from plugin settings."""
    raw = load_plugin_settings().get(SEARCH_HISTORY_KEY)
    if not isinstance(raw, list):
        return []
    project_key = project_key if project_key is not None else current_database_identity()
    entries = []
    for item in raw:
        normalized = normalize_search_history_entry(item)
        if normalized is None:
            continue
        if project_key and normalized.get("project_key") not in ("", project_key):
            continue
        entries.append(normalized)
    if limit is None or int(limit) <= 0:
        return entries
    return entries[: int(limit)]


def save_search_history(entries):
    """Persist recent assembly-search history entries to plugin settings."""
    normalized_entries = []
    for entry in entries or []:
        normalized = normalize_search_history_entry(entry)
        if normalized is None:
            continue
        payload = {
            "query_text": normalized["query_text"],
            "mode": normalized["mode"],
            "created_at": normalized["created_at"],
            "project_key": normalized.get("project_key") or "",
            "project_label": normalized.get("project_label") or "",
            "search_snapshot": normalized.get("search_snapshot")
            or _serialize_search_result(normalized.get("search_result")),
        }
        normalized_entries.append(payload)
        if len(normalized_entries) >= SEARCH_HISTORY_LIMIT:
            break
    settings = load_plugin_settings()
    settings[SEARCH_HISTORY_KEY] = normalized_entries
    save_plugin_settings(settings)


def remember_search_history(query_text, mode, search_result=None):
    """Insert one history entry at the front, storing a result snapshot as well."""
    entry = normalize_search_history_entry(
        {
            "query_text": query_text,
            "mode": mode,
            "created_at": time.time(),
            "project_key": current_database_identity(),
            "project_label": current_database_label(),
            "search_result": search_result,
        }
    )
    if entry is None:
        return load_search_history()
    entries = [
        item
        for item in load_search_history(limit=0, project_key="")
        if not (
            item.get("project_key") == entry["project_key"]
            and item.get("mode") == entry["mode"]
            and item.get("query_text") == entry["query_text"]
        )
    ]
    entries.insert(0, entry)
    save_search_history(entries)
    return load_search_history()


def clear_search_history(project_key=None):
    """Delete persisted assembly-search history entries."""
    settings = load_plugin_settings()
    raw = settings.get(SEARCH_HISTORY_KEY)
    if project_key is None:
        settings[SEARCH_HISTORY_KEY] = []
        save_plugin_settings(settings)
        return

    kept = []
    for item in raw or []:
        normalized = normalize_search_history_entry(item)
        if normalized is None:
            continue
        if normalized.get("project_key") == project_key:
            continue
        kept.append(
            {
                "query_text": normalized["query_text"],
                "mode": normalized["mode"],
                "created_at": normalized["created_at"],
                "project_key": normalized.get("project_key") or "",
                "project_label": normalized.get("project_label") or "",
                "search_snapshot": normalized.get("search_snapshot")
                or _serialize_search_result(normalized.get("search_result")),
            }
        )
    settings[SEARCH_HISTORY_KEY] = kept
    save_plugin_settings(settings)
