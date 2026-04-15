"""Trampoline preview planning, line expansion, and risk analysis."""

from ..asm.assemble import assemble_bytes, assemble_multiline
from ..asm.operands import (
    extract_mnemonic,
    normalize_mem_operand,
    parse_immediate_value,
    pointer_bits,
    processor_key,
    sanitize_asm_line,
    split_operands,
)
from ..asm.rewrite import canonical_x64_reg
from ..backends.pe_backend import prepare_file_patch_segment
from ..constants import (
    PATCH_SEGMENT_NAME,
    PATCH_STUB_ALIGN,
    TRAMPOLINE_ORIG_MARKER_RE,
)
from ..logging_utils import debug_log
from .caves import preview_patch_segment_allocation, next_patch_cursor


def trampoline_risk_notes(entries):
    """Return relocation warnings for replayed instructions that may not be safe."""
    notes = []
    for entry in entries:
        asm = (entry.get("asm") or "").lower()
        mnem = extract_mnemonic(asm)
        if not mnem:
            continue
        if mnem.startswith("j") or mnem in (
            "call",
            "loop",
            "loope",
            "loopne",
            "ret",
            "syscall",
            "sysenter",
        ):
            notes.append(
                "0x%X: `%s` 是控制流相关指令，迁移到代码洞后应人工确认语义。"
                % (entry["ea"], entry["asm"])
            )
            continue
        if "[rip" in asm or "[eip" in asm:
            notes.append(
                "0x%X: `%s` 包含 RIP/EIP 相对寻址，迁移后应人工确认地址是否仍正确。"
                % (entry["ea"], entry["asm"])
            )
    return notes


def parse_stack_delta(line, arch_key):
    """Estimate the stack-pointer delta introduced by one custom instruction."""
    mnem, operands = split_operands(line)
    if not mnem:
        return 0

    ptr_size = 8 if pointer_bits() == 64 else 4
    if mnem == "push":
        return -ptr_size
    if mnem == "pop":
        return ptr_size
    if mnem in ("pushfq", "pushfd"):
        return -ptr_size
    if mnem in ("popfq", "popfd"):
        return ptr_size
    if mnem in ("sub", "add") and len(operands) >= 2:
        dst = operands[0].strip().lower()
        value = parse_immediate_value(operands[1])
        if value is None:
            return 0
        if dst in ("rsp", "esp"):
            return -value if mnem == "sub" else value
    return 0


def x64_effective_pushpop_note(line):
    """Explain how IDA treats 32-bit push/pop spellings in x64 mode."""
    if pointer_bits() != 64:
        return None
    mnem, operands = split_operands(line)
    if mnem not in ("push", "pop") or not operands:
        return None
    reg = operands[0].strip().lower()
    base = canonical_x64_reg(reg)
    if not base or reg == base:
        return None
    return "`%s %s` 在 x64 下实际按 `%s %s` 进行 64 位栈操作。" % (mnem, reg, mnem, base)


def trampoline_custom_risk_notes(custom_lines):
    """Return warnings for custom trampoline code that may corrupt runtime state."""
    notes = []
    stack_delta = 0
    arch_key = processor_key()
    for line in custom_lines:
        note = x64_effective_pushpop_note(line)
        if note:
            notes.append(note)
        stack_delta += parse_stack_delta(line, arch_key)

    if stack_delta != 0:
        direction = "减少" if stack_delta < 0 else "增加"
        notes.append(
            "自定义代码执行后 `rsp/esp` 净%s %d bytes；若没有在跳回前恢复，原函数栈平衡会被破坏。"
            % (direction, abs(stack_delta))
        )
    return notes


def merge_operand_infos(entries):
    """Merge operand rewrite metadata from multiple instructions into one context."""
    merged = []
    seen = set()
    for entry in entries or []:
        for info in entry.get("operand_infos") or []:
            normalized = info.get("normalized")
            asm_operand = info.get("asm_operand")
            if not normalized or not asm_operand:
                continue
            key = (normalized, asm_operand, info.get("size_keyword"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(
                {
                    "index": info.get("index", 0),
                    "display": info.get("display", ""),
                    "normalized": normalized,
                    "asm_operand": asm_operand,
                    "normalized_asm": info.get("normalized_asm", normalize_mem_operand(asm_operand)),
                    "size_keyword": info.get("size_keyword"),
                }
            )
    return merged


def parse_trampoline_orig_marker(line):
    """Parse `{{orig}}` / `{{orig:N}}` placeholders used in trampoline custom code."""
    match = TRAMPOLINE_ORIG_MARKER_RE.match(line.strip())
    if not match:
        return None
    token = (match.group(1) or "all").strip().lower()
    if token == "all":
        return "all"
    index = int(token, 10) - 1
    if index < 0:
        raise RuntimeError("原指令占位符下标从 1 开始，例如 `{{orig:1}}`。")
    return index


def append_trampoline_original_line(lines, line_entries, replayed_entries, entry, source_tag):
    """Append one replayed original instruction into the trampoline body."""
    asm = entry.get("asm") or ""
    if not asm:
        raise RuntimeError("原始指令缺少可回放的汇编文本。")
    lines.append(asm)
    line_entries.append(entry)
    replayed_entries.append(entry)
    debug_log(
        "trampoline.original_insert",
        source=source_tag,
        ea="0x%X" % entry.get("ea", 0),
        asm=asm,
    )


def build_trampoline_lines(custom_text, original_entries, return_ea, include_original):
    """Build the final cave assembly lines and mapping to original entries."""
    custom_lines = [sanitize_asm_line(line) for line in custom_text.splitlines()]
    custom_lines = [line for line in custom_lines if line]
    custom_context = None
    custom_operand_infos = merge_operand_infos(original_entries)
    if custom_operand_infos:
        custom_context = {"asm": "", "operand_infos": custom_operand_infos}

    lines = []
    line_entries = []
    replayed_entries = []
    consumed_indices = set()

    for line in custom_lines:
        marker = parse_trampoline_orig_marker(line)
        if marker is None:
            lines.append(line)
            line_entries.append(custom_context)
            continue

        if marker == "all":
            inserted = 0
            for index, entry in enumerate(original_entries):
                if index in consumed_indices:
                    continue
                append_trampoline_original_line(lines, line_entries, replayed_entries, entry, "{{orig}}")
                consumed_indices.add(index)
                inserted += 1
            if inserted == 0:
                raise RuntimeError("`{{orig}}` 没有可插入的剩余原始指令。")
            continue

        if marker >= len(original_entries):
            raise RuntimeError(
                "原指令占位符 `{{orig:%d}}` 超出范围，当前只覆盖了 %d 条原始指令。"
                % (marker + 1, len(original_entries))
            )
        append_trampoline_original_line(
            lines,
            line_entries,
            replayed_entries,
            original_entries[marker],
            "{{orig:%d}}" % (marker + 1),
        )
        consumed_indices.add(marker)

    if include_original:
        for index, entry in enumerate(original_entries):
            if index in consumed_indices:
                continue
            append_trampoline_original_line(lines, line_entries, replayed_entries, entry, "auto-append")
            consumed_indices.add(index)

    lines.append("jmp 0x%X" % return_ea)
    line_entries.append(None)
    replayed_entries = [original_entries[index] for index in sorted(consumed_indices)]
    return lines, line_entries, replayed_entries


def preview_trampoline_plan(start_ea, region_size, custom_text, original_entries, include_original, write_to_file=False):
    """Preview trampoline bytes without mutating the database."""
    return_ea = start_ea + region_size
    lines, line_entries, replayed_entries = build_trampoline_lines(
        custom_text,
        original_entries,
        return_ea,
        include_original,
    )
    if not lines:
        raise RuntimeError("代码洞内容为空。至少要保留原始指令或填写自定义汇编。")

    custom_lines = [sanitize_asm_line(line) for line in custom_text.splitlines()]
    custom_lines = [line for line in custom_lines if line]
    cave_entries = list(line_entries)
    cave_text = "\n".join(lines)
    arch_key = processor_key()

    if write_to_file:
        file_plan = prepare_file_patch_segment(PATCH_STUB_ALIGN, apply_changes=False)
        seg = file_plan.get("segment")
        cave_start = next_patch_cursor(seg) if seg is not None else file_plan["ea_start"]
        for _ in range(6):
            cave_bytes, _, cave_infos = assemble_multiline(cave_start, cave_text, arch_key, cave_entries)
            required_total = (cave_start - file_plan["ea_start"]) + len(cave_bytes) + PATCH_STUB_ALIGN
            if required_total <= file_plan["raw_size"]:
                break
            file_plan = prepare_file_patch_segment(required_total, apply_changes=False)
            seg = file_plan.get("segment")
            cave_start = next_patch_cursor(seg) if seg is not None else file_plan["ea_start"]
        storage_mode = "file_section"
        segment_name = file_plan["section_name"]
        alloc_base_ea = file_plan["ea_start"]
    else:
        idb_plan = preview_patch_segment_allocation(len(cave_text) + PATCH_STUB_ALIGN)
        seg = idb_plan["segment"]
        cave_start = idb_plan["cave_start"]
        cave_bytes, _, cave_infos = assemble_multiline(cave_start, cave_text, arch_key, cave_entries)
        storage_mode = "idb"
        segment_name = idb_plan["segment_name"]
        alloc_base_ea = idb_plan["alloc_base_ea"]

    entry_bytes, _ = assemble_bytes(start_ea, "jmp 0x%X" % cave_start, arch_key)
    if len(entry_bytes) > region_size:
        raise RuntimeError("入口跳板需要 %d bytes，但当前覆盖范围只有 %d bytes。" % (len(entry_bytes), region_size))

    debug_log(
        "trampoline.preview_plan",
        start_ea="0x%X" % start_ea,
        region_size=region_size,
        cave_start="0x%X" % cave_start,
        cave_size=len(cave_bytes),
        include_original=include_original,
        storage_mode=storage_mode,
        write_to_file=write_to_file,
        segment_name=segment_name,
        custom_text=custom_text,
        line_count=len(lines),
    )
    return {
        "segment": seg,
        "segment_name": segment_name,
        "cave_start": cave_start,
        "cave_end": cave_start + len(cave_bytes),
        "entry_bytes": entry_bytes,
        "cave_bytes": cave_bytes,
        "cave_infos": cave_infos,
        "return_ea": return_ea,
        "risk_notes": (
            trampoline_custom_risk_notes(custom_lines)
            + (
                ["当前代码洞仅存在于 IDB；未写入输入文件时，运行程序或启动调试将跳转到不存在的地址。"]
                if not write_to_file
                else []
            )
            + trampoline_risk_notes(replayed_entries)
        ),
        "lines": lines,
        "include_original": include_original,
        "write_to_file": write_to_file,
        "storage_mode": storage_mode,
        "replayed_entries": replayed_entries,
        "alloc_base_ea": alloc_base_ea,
    }
