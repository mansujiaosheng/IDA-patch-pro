"""Range fill preview/apply helpers that can be used without any UI."""

from ..asm.assemble import assemble_multiline
from ..logging_utils import debug_log, make_trace_id
from .bytes_patch import apply_code_patch, build_nop_bytes
from .rollback import rollback_partial_transaction
from .selection import get_entries_for_line_count
from .transactions import (
    begin_patch_transaction,
    commit_patch_transaction,
    record_transaction_operation,
)


def preview_fill_range(
    start_ea,
    end_ea,
    text,
    arch_key,
    tail_mode="nop",
):
    """Preview filling `[start_ea, end_ea)` with repeated assembled instructions."""
    if end_ea <= start_ea:
        raise RuntimeError("Fill Range 的结束地址必须大于起始地址。")

    region_size = end_ea - start_ea
    line_count = len([line for line in text.splitlines() if line.strip()])
    if line_count <= 0:
        raise RuntimeError("请输入至少一条用于 Fill Range 的汇编指令。")

    current_ea = start_ea
    copies = []
    oversized_copy = None
    aggregated_notes = []
    while current_ea < end_ea:
        original_entries = get_entries_for_line_count(current_ea, line_count)
        copy_bytes, notes, line_infos = assemble_multiline(
            current_ea,
            text,
            arch_key,
            original_entries,
        )
        if not copy_bytes:
            raise RuntimeError("Fill Range 的单次汇编结果为空。")
        if current_ea + len(copy_bytes) > end_ea:
            oversized_copy = {
                "start_ea": current_ea,
                "bytes": copy_bytes,
                "notes": notes,
                "line_infos": line_infos,
            }
            break

        copies.append(
            {
                "start_ea": current_ea,
                "bytes": copy_bytes,
                "notes": notes,
                "line_infos": line_infos,
            }
        )
        for note in notes:
            if note and note not in aggregated_notes:
                aggregated_notes.append(note)
        current_ea += len(copy_bytes)

    if not copies and oversized_copy is not None:
        raise RuntimeError(
            "Fill Range 的单次汇编结果为 %d bytes，已超过当前范围的 %d bytes。"
            % (len(oversized_copy["bytes"]), region_size)
        )

    tail_nop_bytes = b""
    remaining_size = end_ea - current_ea
    if remaining_size > 0:
        if tail_mode != "nop":
            raise RuntimeError(
                "Fill Range 末尾还剩 %d bytes，当前策略不允许自动补齐。"
                % remaining_size
            )
        tail_nop_bytes = build_nop_bytes(current_ea, remaining_size)

    patch_bytes = b"".join(copy["bytes"] for copy in copies) + tail_nop_bytes
    plan = {
        "start_ea": start_ea,
        "end_ea": end_ea,
        "region_size": region_size,
        "tail_mode": tail_mode,
        "copies": copies,
        "copy_count": len(copies),
        "tail_nop_bytes": tail_nop_bytes,
        "remaining_size": remaining_size,
        "notes": aggregated_notes,
        "patch_bytes": patch_bytes,
        "pattern_text": text,
    }
    debug_log(
        "fill_range.preview",
        start_ea="0x%X" % start_ea,
        end_ea="0x%X" % end_ea,
        region_size=region_size,
        copy_count=len(copies),
        tail_size=len(tail_nop_bytes),
        patch_size=len(patch_bytes),
    )
    return plan


def apply_fill_range_plan(plan, write_to_file=False, trace_id=""):
    """Apply a previously prepared Fill Range plan and record a rollback transaction."""
    transaction = None
    applied_count = 0
    file_path = ""
    tx_id = trace_id or make_trace_id("fill", plan["start_ea"])
    try:
        transaction = begin_patch_transaction(
            "fill_range",
            "Fill Range",
            plan["start_ea"],
            trace_id=tx_id,
            meta={
                "start_ea": plan["start_ea"],
                "end_ea": plan["end_ea"],
                "region_size": plan["region_size"],
                "copy_count": plan["copy_count"],
                "tail_mode": plan.get("tail_mode") or "",
                "write_to_file": bool(write_to_file),
            },
        )
        record_transaction_operation(
            transaction,
            plan["start_ea"],
            plan["patch_bytes"],
            write_to_file=write_to_file,
            note="fill_range_patch",
        )
        file_path = apply_code_patch(
            plan["start_ea"],
            plan["patch_bytes"],
            write_to_file=write_to_file,
        )
        applied_count = 1
        commit_patch_transaction(transaction)
        debug_log(
            "fill_range.apply.success",
            trace_id=tx_id,
            start_ea="0x%X" % plan["start_ea"],
            end_ea="0x%X" % plan["end_ea"],
            patch_size=len(plan["patch_bytes"]),
            write_to_file=write_to_file,
            file_path=file_path,
        )
        return file_path
    except Exception:
        try:
            rollback_partial_transaction(transaction, applied_count)
        except Exception:
            pass
        raise
