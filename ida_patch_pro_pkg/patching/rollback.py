"""Rollback helpers and history list presentation logic."""

import time

import ida_auto

from ..ida_adapter import read_idb_bytes, rebase_history_ea, transaction_imagebase
from ..logging_utils import debug_log
from ..trampoline.function_attach import cleanup_trampoline_tail
from .history_store import load_patch_history
from .selection import current_ea, selected_items
from .transactions import (
    apply_operation_bytes,
    history_entry_matches_ea,
    mark_transaction_rolled_back,
    resolve_operation_ea,
)


def rollback_transaction(entry):
    """Revert one previously recorded plugin transaction."""
    operations = list(entry.get("ops") or [])
    if not operations:
        raise RuntimeError("该补丁事务没有可回撤的字节记录。")

    for operation in reversed(operations):
        apply_operation_bytes(operation, revert=True)

    if entry.get("kind") == "trampoline":
        cleanup_trampoline_tail(entry.get("meta") or {})

    ida_auto.auto_wait()
    mark_transaction_rolled_back(entry["tx_id"])
    debug_log(
        "history.rollback",
        tx_id=entry["tx_id"],
        kind=entry.get("kind"),
        target_ea="0x%X" % entry.get("target_ea", 0),
        op_count=len(operations),
    )


def operation_looks_applied(operation, entry_meta=None):
    """Check whether the current database still contains the patched bytes."""
    current = resolve_operation_ea(operation, entry_meta)
    current_bytes = read_idb_bytes(current, operation.get("size", 0)).hex()
    return current_bytes.lower() == (operation.get("new_bytes_hex") or "").lower()


def find_stale_rolled_back_entry(ea=None):
    """Find a rolled-back entry whose bytes still look patched in the current IDB."""
    for entry in reversed(load_patch_history()):
        if entry.get("status") != "rolled_back":
            continue
        if ea is not None and not history_entry_matches_ea(entry, ea):
            continue
        operations = entry.get("ops") or []
        if operations and any(
            operation_looks_applied(operation, entry.get("meta") or {})
            for operation in operations
        ):
            return entry
    return None


def rollback_partial_transaction(transaction, applied_count):
    """Best-effort rollback for a transaction that failed before commit."""
    if not transaction or applied_count <= 0:
        return
    operations = list(transaction.get("ops") or [])[:applied_count]
    for operation in reversed(operations):
        apply_operation_bytes(operation, revert=True)
    if transaction.get("kind") == "trampoline":
        cleanup_trampoline_tail(transaction.get("meta") or {})
    ida_auto.auto_wait()
    debug_log(
        "history.partial_rollback",
        tx_id=transaction.get("tx_id"),
        kind=transaction.get("kind"),
        applied_count=applied_count,
    )


def history_target_ea(ctx):
    """Pick the most relevant EA for a rollback request."""
    items = selected_items(ctx)
    if items:
        return items[0][0]
    return current_ea(ctx)


def describe_history_entry(entry):
    """Build a short user-facing description of one recorded patch transaction."""
    meta = entry.get("meta") or {}
    stored_imagebase = transaction_imagebase(meta)
    target_ea = rebase_history_ea(entry.get("target_ea", 0), stored_imagebase)
    cave_start = rebase_history_ea(meta.get("cave_start"), stored_imagebase)
    parts = [
        "类型: %s" % (entry.get("label") or entry.get("kind") or "unknown"),
        "目标: 0x%X" % (target_ea or 0),
        "操作数: %d" % len(entry.get("ops") or []),
    ]
    if cave_start is not None:
        parts.append("代码洞: 0x%X" % cave_start)
    if meta.get("write_to_file"):
        parts.append("已写回输入文件")
    else:
        parts.append("仅 IDB")
    created_at = entry.get("created_at")
    if created_at:
        parts.append("时间: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_at)))
    return "\n".join(parts)


def entry_runtime_status(entry):
    """Return the effective runtime status shown in the rollback list."""
    status = (entry.get("status") or "").lower()
    if status == "rolled_back":
        operations = entry.get("ops") or []
        if operations and any(
            operation_looks_applied(operation, entry.get("meta") or {})
            for operation in operations
        ):
            return "stale"
    return status or "unknown"


def entry_runtime_status_text(status):
    """Map runtime status to a short Chinese label."""
    mapping = {
        "active": "可回撤",
        "stale": "残留待修复",
        "rolled_back": "已回撤",
        "unknown": "未知",
    }
    return mapping.get(status, status)


def entry_can_rollback(entry):
    """Return whether the history entry can currently be rolled back."""
    return entry_runtime_status(entry) in ("active", "stale")
