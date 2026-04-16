"""Reusable hint and example builders for trampoline/code-cave editing."""

from itertools import zip_longest

from ..asm.operands import sanitize_asm_line
from ..constants import PATCH_SEGMENT_NAME
from ..logging_utils import format_bytes_hex
from .file_storage import file_storage_behavior_text, file_storage_display_text, preview_storage_source_text


def _selected_original_lines(original_entries, limit=2):
    """Return up to `limit` sanitized original instruction lines."""
    selected = []
    for entry in original_entries[:limit]:
        line = sanitize_asm_line(entry.get("text") or entry.get("asm") or "")
        if line:
            selected.append(line)
    return selected


def build_trampoline_example_lines(original_entries):
    """Build practical editor examples for the code-cave workflow."""
    selected = _selected_original_lines(original_entries)
    lines = [
        "例子:",
        "编辑框就是 CE 里 `newmem:` 的主体。",
        "结尾回跳会自动追加，不需要自己写 `jmp returnhere`。",
        "",
        "基础例子:",
    ]
    if len(selected) >= 2:
        lines.extend(
            [
                "- 当前覆盖的原指令例如:",
                "  %s" % selected[0],
                "  %s" % selected[1],
                "- 你可以直接改成:",
                "  mov eax, 1",
                "  %s" % selected[0],
                "  mov eax, 2",
                "  %s" % selected[1],
            ]
        )
    elif selected:
        lines.extend(
            [
                "- 当前覆盖的原指令例如:",
                "  %s" % selected[0],
                "- 你可以直接改成:",
                "  mov eax, 1",
                "  %s" % selected[0],
            ]
        )
    else:
        lines.extend(["- 你可以直接写成:", "  mov eax, 1", "  call my_hook"])

    lines.extend(
        [
            "",
            "高级语法例子:",
            "- `{{orig}}`：把还没补回的原始指令全部插到这里。",
            "  例子:",
            "  call my_hook",
            "  {{orig}}",
            "- `{{orig:1}}`：只把第 1 条被覆盖的原始指令插到这里。",
            "  例子:",
            "  push rax",
            "  {{orig:1}}",
            "  pop rax",
            "- 勾选“末尾自动补齐未保留的原指令并跳回”后，剩余原指令会在末尾自动补回。",
            "- 不勾选时，编辑框里写什么顺序，代码洞里就按什么顺序执行。",
        ]
    )
    return lines


def build_trampoline_hint_text(
    original_entries,
    custom_text,
    preview_plan,
    include_original,
    write_to_file,
):
    """Build the right-side summary panel text for trampoline editing."""
    lines = ["覆盖原始指令:"]
    for index, entry in enumerate(original_entries, 1):
        lines.append("%d. 0x%X: %s" % (index, entry["ea"], entry["text"] or "(unknown)"))

    lines.append("")
    lines.append("入口补丁:")
    lines.append("- 原地址会写入 `jmp code_cave`，其余字节自动补 NOP")
    if original_entries:
        last_entry = original_entries[-1]
        return_ea = last_entry["ea"] + len(last_entry.get("bytes") or b"")
        lines.append("- 返回地址: 0x%X" % return_ea)
    lines.append(
        "- 当前模式: %s"
        % ("末尾自动补齐未保留的原指令" if include_original else "仅按编辑框中的完整顺序执行")
    )
    lines.append(
        "- 存储位置: %s"
        % (file_storage_display_text() if write_to_file else "仅 IDB 内 .patch 段")
    )

    lines.append("")
    lines.append("编辑方式:")
    lines.append("- 编辑框默认已载入当前所选原始汇编")
    lines.append("- 你可以直接插入、删除、重排、改写这些指令")
    lines.append("- 结尾回跳会自动追加，不需要自己写")

    lines.append("")
    lines.append("当前代码洞主体:")
    if custom_text:
        for line in custom_text.splitlines():
            stripped = sanitize_asm_line(line)
            if stripped:
                lines.append("- %s" % stripped)
    else:
        lines.append("- (empty)")

    if preview_plan is not None:
        lines.extend(
            [
                "",
                "预览结果:",
                "- 代码洞段: %s" % (preview_plan.get("segment_name") or ""),
                "- 代码洞起始: 0x%X" % preview_plan["cave_start"],
                "- 代码洞来源: %s" % preview_storage_source_text(preview_plan),
                "- 入口机器码: %s" % format_bytes_hex(preview_plan["entry_bytes"]),
                "- 代码洞总长度: %d bytes" % len(preview_plan["cave_bytes"]),
            ]
        )
        cave_lines = preview_plan.get("lines") or []
        cave_infos = preview_plan.get("cave_infos") or []
        if cave_lines and cave_infos:
            lines.append("")
            lines.append("代码洞机器码预览:")
            for index, (line, info) in enumerate(zip_longest(cave_lines, cave_infos), 1):
                if index > 12:
                    lines.append("...")
                    break
                info = info or {}
                asm_line = sanitize_asm_line(line or info.get("line") or "")
                byte_text = format_bytes_hex((info or {}).get("bytes") or b"")
                if asm_line or byte_text:
                    lines.append("%d. %s -> %s" % (index, asm_line or "(empty)", byte_text or "(none)"))
                note = info.get("note")
                if note:
                    lines.append("   note: %s" % note)
            if len(cave_lines) > 12:
                lines.append("...")
        if preview_plan["risk_notes"]:
            lines.append("")
            lines.append("风险提示:")
            for note in preview_plan["risk_notes"]:
                lines.append("- %s" % note)
    else:
        lines.extend(["", "预览结果:", "- 当前尚未生成新的代码洞预览"])

    lines.append("")
    lines.append("注意:")
    lines.append("- 不写入输入文件时，默认在 IDB 内新增/复用 `%s` 段" % PATCH_SEGMENT_NAME)
    lines.append("- %s" % file_storage_behavior_text())
    lines.append("- `{{orig}}` / `{{orig:N}}` 是高级用法，不写也可以正常使用")
    lines.append("- 代码洞更接近 CE 的 `newmem` 主体：只写你想执行的完整顺序即可")
    lines.append("- 若启用末尾自动补齐原指令，控制流/RIP 相对寻址仍需人工确认")
    lines.append("")
    lines.extend(build_trampoline_example_lines(original_entries))
    return "\n".join(lines)
