"""Reusable assembly preview planning that is independent from any UI."""

from ..asm.assemble import assemble_multiline
from ..logging_utils import debug_log
from .bytes_patch import build_nop_bytes
from .ranges import instruction_range_for_size


def preview_assembly_patch(
    start_ea,
    region_size,
    text,
    arch_key,
    original_entries=None,
    has_selection=False,
    extend_to_instruction_boundary=True,
):
    """Build a full preview plan for a normal inline assembly patch."""
    assembled_bytes, notes, line_infos = assemble_multiline(
        start_ea,
        text,
        arch_key,
        original_entries,
    )

    requested_region_size = int(region_size)
    effective_region_size = requested_region_size
    expansion = None
    expanded = False
    if (
        len(assembled_bytes) > requested_region_size
        and not has_selection
        and extend_to_instruction_boundary
    ):
        expansion = instruction_range_for_size(start_ea, len(assembled_bytes))
        effective_region_size = expansion["size"]
        expanded = effective_region_size > requested_region_size

    tail_nop_bytes = b""
    if len(assembled_bytes) < effective_region_size:
        tail_nop_bytes = build_nop_bytes(
            start_ea + len(assembled_bytes),
            effective_region_size - len(assembled_bytes),
        )

    patch_bytes = assembled_bytes + tail_nop_bytes
    overflow_size = max(0, len(assembled_bytes) - requested_region_size)
    plan = {
        "start_ea": start_ea,
        "requested_region_size": requested_region_size,
        "effective_region_size": effective_region_size,
        "requested_end_ea": start_ea + requested_region_size,
        "effective_end_ea": start_ea + effective_region_size,
        "assembled_bytes": assembled_bytes,
        "patch_bytes": patch_bytes,
        "tail_nop_bytes": tail_nop_bytes,
        "notes": notes,
        "line_infos": line_infos,
        "overflow_size": overflow_size,
        "overflow_end_ea": start_ea + len(assembled_bytes),
        "exceeds_selection": bool(has_selection and overflow_size > 0),
        "expanded_to_instruction_boundary": expanded,
        "expansion": expansion,
        "requires_confirmation": bool(expanded and overflow_size > 0),
    }
    debug_log(
        "assemble_plan.preview",
        start_ea="0x%X" % start_ea,
        requested_region_size=requested_region_size,
        effective_region_size=effective_region_size,
        assembled_size=len(assembled_bytes),
        patch_size=len(patch_bytes),
        expanded=expanded,
        exceeds_selection=plan["exceeds_selection"],
    )
    return plan
