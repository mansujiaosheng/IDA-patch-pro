"""Selection and source-instruction helpers."""

import ida_bytes
import ida_idaapi
import ida_kernwin
import idautils
import idc

from ..asm.operands import build_operand_infos, sanitize_asm_line


def current_ea(ctx):
    """Return the current EA from popup context, falling back to screen EA."""
    ea = getattr(ctx, "cur_ea", ida_idaapi.BADADDR)
    if ea == ida_idaapi.BADADDR:
        ea = ida_kernwin.get_screen_ea()
    return ea


def selected_items(ctx):
    """Return selected disassembly items or the single current instruction."""
    widget = getattr(ctx, "widget", None)
    has_selection, start_ea, end_ea = ida_kernwin.read_range_selection(widget)
    if has_selection and start_ea != ida_idaapi.BADADDR and end_ea > start_ea:
        heads = list(idautils.Heads(start_ea, end_ea))
        if heads:
            return [(ea, ida_bytes.get_item_size(ea)) for ea in heads]
        return [(start_ea, end_ea - start_ea)]

    ea = current_ea(ctx)
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        size = 1
    return [(ea, size)]


def patch_region(ctx):
    """Return patch start, length, user-facing description, and selection state."""
    widget = getattr(ctx, "widget", None)
    has_selection, start_ea, end_ea = ida_kernwin.read_range_selection(widget)
    if has_selection and start_ea != ida_idaapi.BADADDR and end_ea > start_ea:
        return start_ea, end_ea - start_ea, "选中范围 0x%X - 0x%X" % (start_ea, end_ea), True

    ea = current_ea(ctx)
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        size = 1
    return ea, size, "当前地址 0x%X" % ea, False


def hook_region(ctx, min_size=5):
    """Return a hook/trampoline region, auto-extending the current instruction if needed."""
    widget = getattr(ctx, "widget", None)
    has_selection, sel_start, sel_end = ida_kernwin.read_range_selection(widget)
    if has_selection and sel_start != ida_idaapi.BADADDR and sel_end > sel_start:
        region_size = sel_end - sel_start
        if region_size < min_size:
            raise RuntimeError("当前选中范围只有 %d bytes，至少需要 %d bytes 才能写入跳板。" % (region_size, min_size))
        return sel_start, region_size, "选中范围 0x%X - 0x%X" % (sel_start, sel_end), True

    start_ea = current_ea(ctx)
    region_size = 0
    ea = start_ea
    while region_size < min_size:
        size = ida_bytes.get_item_size(ea)
        if size <= 0:
            size = 1
        region_size += size
        ea += size
    return start_ea, region_size, "自动扩展当前地址 0x%X 起的 %d bytes" % (start_ea, region_size), False


def get_original_instruction_text(ea):
    """Return the current disassembly line for an instruction or data item."""
    return (idc.GetDisasm(ea) or "").strip()


def get_original_instruction_bytes(ea):
    """Read the original instruction bytes from the database."""
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        return b""
    buf = ida_bytes.get_bytes(ea, size)
    return bytes(buf) if buf else b""


def get_original_entries(ctx):
    """Build metadata for each selected instruction line."""
    entries = []
    for ea, _ in selected_items(ctx):
        text = get_original_instruction_text(ea)
        asm = sanitize_asm_line(text)
        entries.append(
            {
                "ea": ea,
                "text": text,
                "asm": asm,
                "bytes": get_original_instruction_bytes(ea),
                "operand_infos": build_operand_infos(ea, asm),
            }
        )
    return entries


def get_entries_for_range(start_ea, size):
    """Build instruction entries for a contiguous range."""
    end_ea = start_ea + size
    entries = []
    current = start_ea
    while current < end_ea:
        item_size = ida_bytes.get_item_size(current)
        if item_size <= 0:
            item_size = 1
        text = get_original_instruction_text(current)
        asm = sanitize_asm_line(text)
        entries.append(
            {
                "ea": current,
                "text": text,
                "asm": asm,
                "bytes": get_original_instruction_bytes(current),
                "operand_infos": build_operand_infos(current, asm),
            }
        )
        current += item_size
    return entries


def join_entry_asm_lines(entries):
    """Join entry assembly text into a multiline editor string."""
    return "\n".join(entry.get("asm") or "" for entry in entries if entry.get("asm"))


def build_preview_infos_from_entries(entries):
    """Convert original instruction entries into preview-style structures."""
    return [
        {"line": entry.get("asm") or "", "bytes": entry.get("bytes", b""), "note": None}
        for entry in (entries or [])
        if entry.get("asm")
    ]
