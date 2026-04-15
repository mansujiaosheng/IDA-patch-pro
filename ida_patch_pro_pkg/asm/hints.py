"""Hint text, mnemonic notes, and template suggestions."""

import re

from ..data import MNEMONIC_HINTS, _register_hint
from ..logging_utils import format_bytes_hex
from .operands import (
    extract_mnemonic,
    extract_registers,
    is_immediate_literal,
    is_zero_literal,
    sanitize_asm_line,
    split_operands,
    strip_size_prefix,
)
from .rewrite import canonical_x64_reg, infer_memory_size_keyword, to_x64_reg32


def mnemonic_hint_text(mnem):
    """Return a mnemonic explanation, including common instruction families."""
    if not mnem:
        return "该助记符暂无内置说明。"
    if mnem in MNEMONIC_HINTS:
        return MNEMONIC_HINTS[mnem]
    if re.fullmatch(r"j[a-z]{1,4}", mnem):
        return "条件跳转指令。根据标志寄存器决定是否跳转，常与 `cmp/test` 配合使用。"
    if re.fullmatch(r"set[a-z]{1,4}", mnem):
        return "条件置位指令。根据标志位把目标字节写成 0 或 1，常用于把条件判断结果落到寄存器。"
    if re.fullmatch(r"cmov[a-z]{1,4}", mnem):
        return "条件移动指令。仅当条件满足时才移动源操作数到目标，常用于减少分支。"
    return "该助记符暂无内置说明。"


def build_template_suggestions(current_text, current_bytes, region_size, arch_key, original_entry=None):
    """Build right-panel rewrite suggestions for the current instruction line."""
    mnem, operands = split_operands(current_text)
    if not mnem:
        return []

    overflow = current_bytes is not None and len(current_bytes) > region_size
    suggestions = []

    if mnem == "mov" and len(operands) >= 2 and arch_key == "x86/x64":
        dst, src = operands[0], operands[1]
        dst64 = canonical_x64_reg(dst)
        dst32 = to_x64_reg32(dst)
        size_kw = infer_memory_size_keyword(original_entry, dst)

        if dst64 and is_zero_literal(src):
            if overflow:
                suggestions.append(
                    "长度不够时优先模板: `xor %s, %s`。它能把 `%s` 清零，通常明显短于 `mov %s, 0`。"
                    % (dst32 or dst, dst32 or dst, dst64, dst)
                )
            suggestions.append(
                "固定模板: `xor %s, %s`。这是把寄存器置 0 的首选短写法。"
                % (dst32 or dst, dst32 or dst)
            )
            if dst32:
                suggestions.append(
                    "固定模板: `mov %s, 0`。写 32 位寄存器时会自动清零对应 64 位高半部分。"
                    % dst32
                )
            suggestions.append(
                "如果必须保留 `mov %s, 0` 这种完整写法，请扩大选区或接受继续覆盖后续字节。"
                % dst
            )
            return suggestions

        if dst64 and is_immediate_literal(src):
            if overflow:
                suggestions.append(
                    "长度不够时可先尝试更短模板: `mov %s, %s`。x64 下写 32 位寄存器会清零高 32 位。"
                    % (dst32 or dst, src)
                )
            if dst32:
                suggestions.append(
                    "固定模板: `mov %s, %s`。适合你只是想把一个立即数放进寄存器且不关心高 32 位原值的场景。"
                    % (dst32, src)
                )
            suggestions.append(
                "如果要把更大的立即数完整写进 `%s`，最稳的方法仍是扩大选区。"
                % dst
            )
            return suggestions

        if dst64 and canonical_x64_reg(src):
            suggestions.append(
                "寄存器到寄存器的 `mov` 通常已经比较短；如果这里仍超长，更多是当前地址空间不够，建议扩大选区。"
            )
            suggestions.append(
                "如果你的真实目的只是清空 `%s`，可直接改成 `xor %s, %s`。"
                % (dst64, dst32 or dst, dst32 or dst)
            )
            return suggestions

        if "[" in dst and "]" in dst and is_immediate_literal(src):
            if size_kw in ("byte", "word", "dword", "qword"):
                suggestions.append(
                    "固定模板: `mov %s ptr %s, %s`。对内存写立即数时，通常必须显式写出大小。"
                    % (size_kw, strip_size_prefix(dst), src)
                )
            else:
                suggestions.append(
                    "对内存写立即数时，通常必须显式写出大小，例如 `mov byte/dword/qword ptr [mem], imm`。"
                )
            return suggestions

        suggestions.append("`mov` 涉及内存寻址时，长度往往由地址编码决定，最直接的办法通常是扩大选区。")
        suggestions.append("如果你只是想把寄存器清零，优先考虑 `xor <reg32>, <reg32>` 这类短模板。")
        return suggestions

    if mnem == "mov" and len(operands) >= 2 and arch_key in ("ARM/Thumb", "AArch64"):
        dst, src = operands[0], operands[1]
        suggestions.append("ARM/AArch64 的 `mov` 长度通常更稳定；若超出范围，多半需要扩大选区而不是换助记符。")
        if is_zero_literal(src):
            suggestions.append("固定模板: `eor %s, %s, %s`。当你只是想清零寄存器时可作为等价写法。" % (dst, dst, dst))
        return suggestions

    if mnem == "mov" and len(operands) >= 2 and arch_key == "MIPS":
        dst, src = operands[0], operands[1]
        suggestions.append("MIPS 的 `mov/li` 经常是伪指令，可能展开成多条真实指令；超长时应优先检查是否需要扩大选区。")
        if is_zero_literal(src):
            suggestions.append("固定模板: `move %s, $zero`。当你只是想置零寄存器时可直接使用。" % dst)
        return suggestions

    if mnem == "lea" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        suggestions.append("固定模板: `lea %s, [base+index*scale+disp]`。适合做地址计算，而不是读内存。" % dst)
        suggestions.append("如果你的真实目的其实是取内存里的值，应改用 `mov %s, %s`。" % (dst, src))
        return suggestions

    if mnem == "xor" and len(operands) >= 2:
        left, right = operands[0], operands[1]
        suggestions.append("固定模板: `xor dst, src`。适合做按位异或。")
        if left.lower() == right.lower():
            suggestions.append("当前写法也是经典清零模板: `xor %s, %s`。" % (left, right))
        else:
            suggestions.append("如果你的真实目的只是清零 `%s`，可改成 `xor %s, %s`。" % (left, left, left))
        return suggestions

    if mnem == "add" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        suggestions.append("固定模板: `add %s, %s`。适合给目标加上寄存器或立即数。" % (dst, src))
        suggestions.append("如果你只是想加 1，可考虑 `inc %s`，但要注意它与 `add` 的标志位行为并不完全相同。" % dst)
        return suggestions

    if mnem == "sub" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        suggestions.append("固定模板: `sub %s, %s`。适合从目标减去寄存器或立即数。" % (dst, src))
        suggestions.append("如果你只是想减 1，可考虑 `dec %s`，但要注意它与 `sub` 的标志位行为并不完全相同。" % dst)
        return suggestions

    if mnem == "cmp" and len(operands) >= 2:
        left, right = operands[0], operands[1]
        suggestions.append("固定模板: `cmp %s, %s`。适合做大小/相等比较，然后配合条件跳转。" % (left, right))
        suggestions.append("常见配套模板: `cmp %s, %s` 后接 `jz/jnz/jg/jl/...`。" % (left, right))
        return suggestions

    if mnem == "test" and len(operands) >= 2:
        left, right = operands[0], operands[1]
        suggestions.append("固定模板: `test %s, %s`。适合做按位测试，只更新标志位，不保存结果。" % (left, right))
        suggestions.append("常见零值判断模板: `test reg, reg` 后接 `jz/jnz`。")
        return suggestions

    if mnem in ("jz", "je", "jnz", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "js", "jns") and operands:
        suggestions.append("固定模板: `%s target`。条件跳转通常依赖前面的 `cmp/test` 结果。" % mnem)
        suggestions.append("常见配套模板: 先 `cmp/test`，再 `%s label`。" % mnem)
        return suggestions

    if mnem == "jmp" and operands:
        suggestions.append("固定模板: `jmp target`。无条件跳转会直接改变控制流。")
        suggestions.append("如果目标是寄存器，也可用 `jmp reg` 做间接跳转。")
        return suggestions

    if mnem == "call" and operands:
        suggestions.append("固定模板: `call target`。直接调用函数或子过程。")
        suggestions.append("如果目标在寄存器里，也可用 `call reg`。")
        return suggestions

    if mnem == "push" and operands:
        suggestions.append("固定模板: `push src`。常用于保存寄存器、传参或构造栈数据。")
        if arch_key == "x86/x64":
            suggestions.append("常见配套模板: `push imm` / `pop reg`，可把一个立即数放进寄存器。")
        return suggestions

    if mnem == "pop" and operands:
        suggestions.append("固定模板: `pop dst`。常用于恢复寄存器或从栈中取值。")
        suggestions.append("常见配套模板: `push src` 后接 `pop dst`。")
        return suggestions

    if mnem == "ret":
        suggestions.append("固定模板: `ret`。直接从当前函数返回。")
        suggestions.append("如果调用约定要求回收参数，某些平台会见到 `ret imm`。")
        return suggestions

    if mnem == "nop":
        suggestions.append("固定模板: `nop`。适合补齐长度、屏蔽逻辑或做对齐填充。")
        suggestions.append("如果需要覆盖更长范围，可以连续使用多条 `nop`。")
        return suggestions

    if mnem in ("and", "or") and len(operands) >= 2:
        suggestions.append("固定模板: `%s %s, %s`。适合位运算、掩码处理和标志位修改。" % (mnem, operands[0], operands[1]))
        return suggestions

    if mnem in ("movaps", "movups", "movdqa", "movdqu") and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        vector_dst = strip_size_prefix(dst)
        suggestions.append(
            "`%s` 只能在向量寄存器和对应内存块之间搬运，不能直接把立即数当源操作数。"
            % mnem
        )
        if "[" in dst and "]" in dst and is_immediate_literal(src):
            suggestions.append(
                "如果你想把这块 16 字节内存清零，常见模板是 `pxor xmm0, xmm0` 后再 `%s xmmword ptr %s, xmm0`。"
                % (mnem, vector_dst)
            )
            suggestions.append(
                "如果你只是想给其中某个标量槽写入 1，请改用 `mov byte/word/dword/qword ptr %s, 1` 并明确大小。"
                % vector_dst
            )
        return suggestions

    if mnem in ("imul", "mul", "div", "idiv"):
        suggestions.append("这类乘除法指令通常受特定寄存器约束，修改前应先确认调用约定和结果寄存器。")
        if arch_key == "x86/x64":
            suggestions.append("x86/x64 下常见固定模板会隐式使用 `rax/rdx`。")
        return suggestions

    suggestions.append("当前助记符 `%s` 暂无专门模板，但右侧的原机器码、寄存器作用和长度提示仍可作为改写参考。" % mnem)
    return suggestions


def length_warning_text(patch_size, region_size, has_selection, start_ea, effective_region_size=None):
    """Return a user-facing summary of length fit or overflow."""
    effective_region_size = int(effective_region_size or region_size)
    if effective_region_size > region_size and not has_selection and patch_size > region_size:
        effective_end = start_ea + effective_region_size - 1
        if patch_size < effective_region_size:
            return (
                "新汇编已超出当前指令 %d bytes；"
                " 预览会按完整指令边界扩展到 0x%X，并在末尾自动补 %d bytes NOP。"
                % (patch_size - region_size, effective_end, effective_region_size - patch_size)
            )
        return (
            "新汇编已超出当前指令 %d bytes；"
            " 预览会按完整指令边界扩展到 0x%X。"
            % (patch_size - region_size, effective_end)
        )

    if patch_size == region_size:
        return "长度匹配当前可覆盖范围。"
    if patch_size < region_size:
        return "新汇编比原范围短 %d bytes，剩余部分会自动补 NOP。" % (region_size - patch_size)

    overflow_end = start_ea + patch_size - 1
    if has_selection:
        return (
            "新汇编超出选区 %d bytes，当前不会允许写入；"
            " 需要扩大选区到至少 0x%X，或改用代码注入。"
            % (patch_size - region_size, overflow_end)
        )
    return (
        "新汇编超出当前指令 %d bytes，将继续覆盖到 0x%X；"
        " 若不想继续覆盖，可改用代码注入。"
        % (patch_size - region_size, overflow_end)
    )


def build_hint_text(
    original_entries,
    current_text,
    preview_bytes,
    preview_infos,
    region_size,
    has_selection,
    start_ea,
    arch_key,
    preview_plan=None,
):
    """Assemble the full right-side help panel text."""
    current_lines = [sanitize_asm_line(line) for line in current_text.splitlines()]
    current_lines = [line for line in current_lines if line]
    preview_infos = preview_infos or []
    effective_region_size = (
        int(preview_plan.get("effective_region_size", region_size))
        if preview_plan is not None
        else region_size
    )

    line_count = max(len(original_entries), len(current_lines), len(preview_infos), 1)
    lines = []

    if current_text.strip() or preview_bytes is not None:
        lines.append(
            "原始行数: %d | 当前编辑行数: %d"
            % (len(original_entries), len(current_lines))
        )
        if preview_bytes is not None:
            lines.append(
                "总长度提示: %s"
                % length_warning_text(
                    len(preview_bytes),
                    region_size,
                    has_selection,
                    start_ea,
                    effective_region_size=effective_region_size,
                )
            )
        elif current_text.strip():
            lines.append("总长度提示: 当前输入还无法成功汇编")
        if preview_plan and preview_plan.get("expanded_to_instruction_boundary"):
            lines.append(
                "范围扩展: 当前指令不够，预览会自动对齐到完整指令边界，实际写入范围到 0x%X。"
                % (preview_plan["effective_end_ea"] - 1)
            )

    for index in range(line_count):
        original_entry = original_entries[index] if index < len(original_entries) else None
        current_line = current_lines[index] if index < len(current_lines) else ""
        preview_info = preview_infos[index] if index < len(preview_infos) else None

        if lines:
            lines.append("")
        title = "第 %d 行" % (index + 1)
        if original_entry:
            title += " @ 0x%X" % original_entry["ea"]
        lines.append(title)

        if original_entry:
            lines.append("原指令: %s" % (original_entry["text"] or "(unknown)"))
            lines.append("原机器码: %s" % format_bytes_hex(original_entry["bytes"]))
        else:
            lines.append("原指令: (无)")
            lines.append("原机器码: (none)")

        if current_line:
            lines.append("当前编辑: %s" % current_line)
            if preview_info:
                lines.append("新机器码预览: %s" % format_bytes_hex(preview_info["bytes"]))
                if preview_info.get("note"):
                    lines.append("兼容说明: %s" % preview_info["note"])
            else:
                lines.append("新机器码预览: 当前输入还无法成功汇编")

        source_text = current_line or (original_entry["asm"] if original_entry else "")
        hint_key = extract_mnemonic(source_text)
        if hint_key:
            lines.append("指令说明: %s" % mnemonic_hint_text(hint_key))

        regs = extract_registers(source_text, arch_key)
        if regs:
            lines.append("寄存器提示:")
            for reg in regs:
                lines.append("%s: %s" % (reg, _register_hint(reg, arch_key) or "暂无说明。"))

        per_line_region = len(original_entry["bytes"]) if original_entry and original_entry["bytes"] else region_size
        per_line_bytes = preview_info["bytes"] if preview_info else None
        suggestions = build_template_suggestions(source_text, per_line_bytes, per_line_region, arch_key, original_entry)
        if suggestions:
            lines.append("模板建议:")
            for suggestion in suggestions:
                lines.append("- %s" % suggestion)

    return "\n".join(lines)
