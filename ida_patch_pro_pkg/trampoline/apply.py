"""Core trampoline apply flow shared by UI and future non-UI callers."""

import ida_auto
import idc

from ..constants import PATCH_STUB_ALIGN
from ..ida_adapter import input_file_path, read_file_bytes, read_idb_bytes
from ..logging_utils import debug_log
from ..patching.bytes_patch import apply_code_patch, build_nop_bytes
from ..patching.rollback import rollback_partial_transaction
from ..patching.transactions import (
    begin_patch_transaction,
    commit_patch_transaction,
    record_transaction_operation,
)
from .caves import ensure_patch_segment, next_patch_cursor
from .file_storage import prepare_file_trampoline_storage
from .function_attach import attach_cave_to_owner_function


def _hex_preview(data, limit=64):
    """Return a short hex preview suitable for error messages."""
    text = bytes(data).hex()
    if len(text) <= limit:
        return text
    return "%s..." % text[:limit]


def _refresh_plan_if_needed(start_ea, plan, new_cave_start, plan_builder):
    """Rebuild the trampoline plan when storage preparation moved the cave."""
    if new_cave_start == plan["cave_start"]:
        return plan
    if plan_builder is None:
        raise RuntimeError("代码洞位置在应用前发生变化，请先重新预览再应用。")

    refreshed = plan_builder()
    if refreshed["cave_start"] != new_cave_start:
        raise RuntimeError(
            "代码洞位置在应用前发生变化：预期 0x%X，重新计算后得到 0x%X。请重新预览再应用。"
            % (new_cave_start, refreshed["cave_start"])
        )
    debug_log(
        "trampoline.apply.plan_refresh",
        start_ea="0x%X" % start_ea,
        old_cave_start="0x%X" % plan["cave_start"],
        new_cave_start="0x%X" % refreshed["cave_start"],
        storage_mode=refreshed.get("storage_mode") or "",
    )
    return refreshed


def prepare_trampoline_apply_plan(start_ea, plan, plan_builder=None):
    """Prepare final storage and return a plan that is safe to apply."""
    storage_mode = plan.get("storage_mode")
    if storage_mode == "idb":
        seg = ensure_patch_segment(len(plan["cave_bytes"]) + PATCH_STUB_ALIGN)
        return _refresh_plan_if_needed(start_ea, plan, next_patch_cursor(seg), plan_builder)

    if storage_mode == "file_section":
        required_total = (
            (plan["cave_start"] - plan.get("alloc_base_ea", plan["cave_start"]))
            + len(plan["cave_bytes"])
            + PATCH_STUB_ALIGN
        )
        file_info = prepare_file_trampoline_storage(
            required_total,
            preferred_ea=start_ea,
            apply_changes=True,
        )
        return _refresh_plan_if_needed(start_ea, plan, file_info["cave_start"], plan_builder)

    if storage_mode == "file_cave":
        required_total = len(plan["cave_bytes"]) + PATCH_STUB_ALIGN
        file_info = prepare_file_trampoline_storage(
            required_total,
            preferred_ea=start_ea,
            apply_changes=False,
        )
        return _refresh_plan_if_needed(start_ea, plan, file_info["cave_start"], plan_builder)

    return plan


def _validate_idb_bytes(ea, expected, label):
    """Ensure the current IDB bytes already match the expected payload."""
    current = read_idb_bytes(ea, len(expected))
    if current != expected:
        raise RuntimeError(
            "%s 写入后 IDB 校验失败：EA=0x%X\n当前: %s\n期望: %s"
            % (label, ea, _hex_preview(current), _hex_preview(expected))
        )


def _validate_file_bytes(operation, label):
    """Ensure file-backed chunks already contain the newly written bytes."""
    if not operation.get("write_to_file"):
        return

    file_chunks = operation.get("file_chunks") or []
    if not file_chunks:
        return

    path = operation.get("file_path") or input_file_path()
    if not path:
        raise RuntimeError("%s 写入后文件校验失败：没有可读的输入文件路径。" % label)

    for chunk in file_chunks:
        offset = int(chunk.get("offset") or 0)
        expected = bytes.fromhex((chunk.get("new_bytes_hex") or "").strip())
        current = read_file_bytes(path, offset, len(expected))
        if current != expected:
            raise RuntimeError(
                "%s 写入后文件校验失败：offset=0x%X\n当前: %s\n期望: %s"
                % (label, offset, _hex_preview(current), _hex_preview(expected))
            )


def _validate_operation_applied(operation, label):
    """Validate one just-applied operation against both IDB and file state."""
    expected = bytes.fromhex((operation.get("new_bytes_hex") or "").strip())
    _validate_idb_bytes(int(operation.get("ea") or 0), expected, label)
    _validate_file_bytes(operation, label)


def apply_trampoline_patch(
    start_ea,
    region_size,
    plan,
    trace_id="",
    plan_builder=None,
    transaction_kind="trampoline",
    transaction_label="代码注入",
    transaction_meta=None,
):
    """Apply one trampoline plan and validate cave + entry before commit."""
    transaction = None
    applied_count = 0
    file_path = ""
    plan = prepare_trampoline_apply_plan(start_ea, plan, plan_builder=plan_builder)
    cave_start = plan["cave_start"]
    cave_end = plan["cave_end"]
    write_to_file = bool(plan.get("write_to_file"))

    transaction_meta = dict(transaction_meta or {})
    try:
        base_meta = {
            "start_ea": start_ea,
            "region_size": region_size,
            "write_to_file": write_to_file,
            "cave_start": cave_start,
            "cave_end": cave_end,
            "owner_ea": start_ea,
            "storage_mode": plan.get("storage_mode") or "",
        }
        base_meta.update(transaction_meta)
        transaction = begin_patch_transaction(
            transaction_kind,
            transaction_label,
            start_ea,
            trace_id=trace_id,
            meta=base_meta,
        )

        record_transaction_operation(
            transaction,
            cave_start,
            plan["cave_bytes"],
            write_to_file=write_to_file,
            note="trampoline_cave",
        )
        cave_operation = transaction["ops"][-1]
        applied_count = 1
        file_path = apply_code_patch(
            cave_start,
            plan["cave_bytes"],
            write_to_file=write_to_file,
        ) or file_path
        _validate_operation_applied(cave_operation, "Trampoline payload")
        idc.set_name(cave_start, "patch_cave_%X" % start_ea, idc.SN_NOWARN)

        entry_patch = bytes(plan["entry_bytes"])
        if len(entry_patch) < region_size:
            entry_patch += build_nop_bytes(start_ea + len(entry_patch), region_size - len(entry_patch))

        record_transaction_operation(
            transaction,
            start_ea,
            entry_patch,
            write_to_file=write_to_file,
            note="trampoline_entry",
        )
        entry_operation = transaction["ops"][-1]
        applied_count = 2
        file_path = apply_code_patch(
            start_ea,
            entry_patch,
            write_to_file=write_to_file,
        ) or file_path
        _validate_operation_applied(entry_operation, "Trampoline entry")

        ida_auto.auto_wait()
        if not attach_cave_to_owner_function(start_ea, cave_start, cave_end):
            raise RuntimeError(
                "代码注入已写入，但无法把 0x%X-0x%X 挂接到原函数 0x%X。"
                % (cave_start, cave_end, start_ea)
            )

        commit_patch_transaction(transaction)
        debug_log(
            "trampoline.apply.verified",
            trace_id=trace_id,
            start_ea="0x%X" % start_ea,
            cave_start="0x%X" % cave_start,
            cave_size=len(plan["cave_bytes"]),
            entry_size=len(entry_patch),
            write_to_file=write_to_file,
            file_path=file_path,
        )
        return {
            "file_path": file_path,
            "cave_start": cave_start,
            "cave_end": cave_end,
            "entry_size": len(entry_patch),
            "plan": plan,
        }
    except Exception:
        rollback_partial_transaction(transaction, applied_count)
        raise
