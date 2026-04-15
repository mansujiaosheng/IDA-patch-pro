"""Instruction-range helpers shared by patch planning and search."""

import ida_bytes
import idautils


def item_size_or_one(ea):
    """Return the current item size, falling back to one byte for unknown data."""
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        return 1
    return size


def instruction_range_for_size(start_ea, min_size):
    """Extend forward from `start_ea` until full instruction boundaries cover `min_size` bytes."""
    if min_size <= 0:
        return {"start_ea": start_ea, "end_ea": start_ea, "size": 0, "items": []}

    end_target = start_ea + int(min_size)
    current = start_ea
    items = []
    while current < end_target:
        size = item_size_or_one(current)
        items.append({"ea": current, "size": size})
        current += size
    return {
        "start_ea": start_ea,
        "end_ea": current,
        "size": current - start_ea,
        "items": items,
    }


def iter_instruction_heads(start_ea, end_ea, code_only=True):
    """Yield instruction/data heads inside the requested half-open range."""
    for ea in idautils.Heads(start_ea, end_ea):
        if code_only and not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
        yield ea
