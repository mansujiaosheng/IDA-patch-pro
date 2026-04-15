"""Patch transaction capture, persistence, and operation replay helpers."""

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
from .bytes_patch import patch_bytes_as_code
from .history_store import load_patch_history, save_patch_history


def resolve_operation_ea(operation, entry_meta=None):
    """Resolve a recorded operation EA into the current database address."""
    stored_imagebase = operation.get("imagebase")
    if stored_imagebase is None:
        stored_imagebase = transaction_imagebase(entry_meta)
    return rebase_history_ea(operation.get("ea"), int(stored_imagebase or 0))


def capture_patch_operation(ea, patch_bytes, write_to_file=False, note=""):
    """Capture pre-patch bytes so the operation can later be rolled back."""
    seg = ida_segment.getseg(ea)
    operation = {
        "ea": ea,
        "imagebase": current_imagebase(),
        "segment_name": segment_name(seg),
        "segment_offset": (ea - seg.start_ea) if seg is not None else 0,
        "size": len(patch_bytes),
        "old_bytes_hex": read_idb_bytes(ea, len(patch_bytes)).hex(),
        "new_bytes_hex": bytes(patch_bytes).hex(),
        "write_to_file": bool(write_to_file),
        "file_path": "",
        "file_chunks": [],
        "note": note or "",
    }
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


def record_transaction_operation(transaction, ea, patch_bytes, write_to_file=False, note=""):
    """Append one operation snapshot into a transaction before applying it."""
    transaction["ops"].append(
        capture_patch_operation(
            ea,
            patch_bytes,
            write_to_file=write_to_file,
            note=note,
        )
    )


def commit_patch_transaction(transaction):
    """Persist a completed patch transaction so it can be rolled back later."""
    if not transaction.get("ops"):
        return
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
