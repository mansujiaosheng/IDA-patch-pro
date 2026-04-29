"""Patch transaction capture, persistence, and operation replay helpers."""

import hashlib
import os
import time

import ida_segment

from ..backends.filemap import build_file_patch_chunks
from ..ida_adapter import (
    current_imagebase,
    input_file_path,
    read_file_bytes,
    read_idb_bytes,
    rebase_history_ea,
    segment_name,
    transaction_imagebase,
)
from ..logging_utils import debug_log, make_trace_id
from .bytes_patch import patch_bytes_as_code, patch_bytes_as_data
from .history_store import load_patch_history, save_patch_history


def resolve_operation_ea(operation, entry_meta=None):
    """Resolve a recorded operation EA into the current database address."""
    stored_imagebase = operation.get("imagebase")
    if stored_imagebase is None:
        stored_imagebase = transaction_imagebase(entry_meta)
    return rebase_history_ea(operation.get("ea"), int(stored_imagebase or 0))


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _capture_input_file_baseline():
    path = input_file_path() or ""
    if not path or not os.path.isfile(path):
        return {
            "path": path,
            "name": os.path.basename(path) if path else "",
            "size": None,
            "sha256": None,
        }

    return {
        "path": path,
        "name": os.path.basename(path),
        "size": os.path.getsize(path),
        "sha256": _sha256_file(path),
    }


def _transaction_writes_to_file(transaction):
    """Return whether one transaction contains file-backed operations."""
    for operation in transaction.get("ops") or []:
        if operation.get("write_to_file"):
            return True
    return False


def _join_old_bytes_from_file_chunks(file_chunks):
    """Merge contiguous file-chunk baselines into one old-bytes snapshot."""
    if not file_chunks:
        return None

    merged = bytearray()
    expected_offset = None
    for chunk in file_chunks:
        offset = int(chunk.get("offset") or 0)
        old_hex = (chunk.get("old_bytes_hex") or "").strip()
        if not old_hex:
            return None
        data = bytes.fromhex(old_hex)
        if expected_offset is not None and offset != expected_offset:
            return None
        merged.extend(data)
        expected_offset = offset + len(data)
    return bytes(merged)


def capture_patch_operation(ea, patch_bytes, write_to_file=False, note="", patch_mode="code"):
    """Capture pre-patch bytes so the operation can later be rolled back."""
    patch_bytes = bytes(patch_bytes)
    seg = ida_segment.getseg(ea)
    operation = {
        "ea": ea,
        "imagebase": current_imagebase(),
        "segment_name": segment_name(seg),
        "segment_offset": (ea - seg.start_ea) if seg is not None else 0,
        "size": len(patch_bytes),
        "old_bytes_hex": "",
        "new_bytes_hex": patch_bytes.hex(),
        "write_to_file": bool(write_to_file),
        "file_path": "",
        "file_chunks": [],
        "note": note or "",
        "patch_mode": patch_mode or "code",
    }

    old_bytes = read_idb_bytes(ea, len(patch_bytes))
    if write_to_file:
        path = input_file_path()
        if not path or not os.path.isfile(path):
            raise RuntimeError("当前 IDB 没有关联输入文件，无法写回文件。")

        file_chunks = []
        for offset, data in build_file_patch_chunks(ea, patch_bytes):
            file_chunks.append(
                {
                    "offset": offset,
                    "old_bytes_hex": read_file_bytes(path, offset, len(data)).hex(),
                    "new_bytes_hex": data.hex(),
                }
            )
        operation["file_path"] = path
        operation["file_chunks"] = file_chunks

        file_old_bytes = _join_old_bytes_from_file_chunks(file_chunks)
        if file_old_bytes is not None and len(file_old_bytes) == len(patch_bytes):
            old_bytes = file_old_bytes

    operation["old_bytes_hex"] = old_bytes.hex()
    return operation


def apply_operation_bytes(operation, revert=False):
    """Apply one recorded operation either forward or backward."""
    current_ea = resolve_operation_ea(operation)
    patch_bytes = bytes.fromhex(
        operation["old_bytes_hex"] if revert else operation["new_bytes_hex"]
    )
    if operation.get("write_to_file") and operation.get("file_chunks"):
        path = operation.get("file_path") or input_file_path()
        if not path or not os.path.isfile(path):
            raise RuntimeError("回撤失败：输入文件不存在。")
        with open(path, "r+b") as fh:
            for chunk in operation["file_chunks"]:
                chunk_bytes = bytes.fromhex(
                    chunk["old_bytes_hex"] if revert else chunk["new_bytes_hex"]
                )
                fh.seek(chunk["offset"])
                fh.write(chunk_bytes)
    if (operation.get("patch_mode") or "code") == "data":
        patch_bytes_as_data(current_ea, patch_bytes)
    else:
        patch_bytes_as_code(current_ea, patch_bytes)


def begin_patch_transaction(kind, label, target_ea, trace_id="", meta=None):
    """Create a history transaction that groups one logical patch action."""
    meta = dict(meta or {})
    meta.setdefault("imagebase", current_imagebase())
    return {
        "tx_id": trace_id or make_trace_id(kind, target_ea),
        "kind": kind,
        "label": label,
        "target_ea": target_ea,
        "created_at": time.time(),
        "status": "active",
        "ops": [],
        "meta": meta,
    }


def record_transaction_operation(
    transaction,
    ea,
    patch_bytes,
    write_to_file=False,
    note="",
    patch_mode="code",
):
    """Append one operation snapshot into a transaction before applying it."""
    if write_to_file:
        meta = transaction.setdefault("meta", {})
        if "input_file_before" not in meta:
            meta["input_file_before"] = _capture_input_file_baseline()

    transaction["ops"].append(
        capture_patch_operation(
            ea,
            patch_bytes,
            write_to_file=write_to_file,
            note=note,
            patch_mode=patch_mode,
        )
    )


def commit_patch_transaction(transaction):
    """Persist a completed patch transaction so it can be rolled back later."""
    if not transaction.get("ops"):
        return
    meta = transaction.setdefault("meta", {})
    if _transaction_writes_to_file(transaction) and "input_file_after" not in meta:
        meta["input_file_after"] = _capture_input_file_baseline()
    entries = load_patch_history()
    entries.append(transaction)
    save_patch_history(entries)
    debug_log(
        "history.commit",
        tx_id=transaction["tx_id"],
        kind=transaction["kind"],
        target_ea="0x%X" % transaction["target_ea"],
        op_count=len(transaction["ops"]),
    )


def history_entry_matches_ea(entry, ea):
    """Return whether the address overlaps any operation or cave range of the entry."""
    meta = entry.get("meta") or {}
    for operation in entry.get("ops") or []:
        start = resolve_operation_ea(operation, meta)
        if start is None:
            continue
        size = operation.get("size", 0)
        if start <= ea < start + max(size, 1):
            return True
    stored_imagebase = transaction_imagebase(meta)
    cave_start = rebase_history_ea(meta.get("cave_start"), stored_imagebase)
    cave_end = rebase_history_ea(meta.get("cave_end"), stored_imagebase)
    if cave_start is not None and cave_end is not None and cave_start <= ea < cave_end:
        return True
    return False


def find_active_history_entry(ea=None):
    """Find the latest active transaction, preferring one that covers `ea`."""
    for entry in reversed(load_patch_history()):
        if entry.get("status") != "active":
            continue
        if ea is None or history_entry_matches_ea(entry, ea):
            return entry
    return None


def mark_transaction_rolled_back(tx_id):
    """Mark a transaction as rolled back without deleting its history record."""
    entries = load_patch_history()
    changed = False
    for entry in entries:
        if entry.get("tx_id") != tx_id:
            continue
        entry["status"] = "rolled_back"
        entry["rolled_back_at"] = time.time()
        changed = True
        break
    if changed:
        save_patch_history(entries)
