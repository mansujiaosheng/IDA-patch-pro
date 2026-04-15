"""Assembly rewrite helpers, including symbol resolution and rel32 fallback."""

import re
import struct

import ida_idaapi
import idc

from ..data import _register_hint
from ..logging_utils import debug_log
from .operands import (
    extract_mnemonic,
    infer_operand_size_keyword,
    is_immediate_literal,
    normalize_mem_operand,
    parse_immediate_value,
    split_operands,
    split_size_prefix,
    strip_size_prefix,
)


def rewrite_line_for_assembly(line, arch_key, original_entry=None):
    """Rewrite user text into a more assembler-friendly form before assembly."""
    if not original_entry:
        return line

    mnem, operands = split_operands(line)
    if not mnem or not operands:
        return line

    operand_infos = original_entry.get("operand_infos") or []
    if not operand_infos:
        return line

    rewritten = []
    for operand in operands:
        size_prefix, core = split_size_prefix(operand)
        normalized = normalize_mem_operand(core)
        replacement = None
        for info in operand_infos:
            if info.get("normalized") == normalized and info.get("asm_operand"):
                replacement = info["asm_operand"]
                break
        if replacement is None:
            rewritten.append(operand)
            continue
        if size_prefix:
            rewritten.append("%s %s" % (size_prefix, replacement))
        else:
            rewritten.append(replacement)

    result = "%s %s" % (mnem, ", ".join(rewritten))
    if result != line:
        debug_log(
            "rewrite_line",
            ea="0x%X" % original_entry.get("ea", 0) if original_entry.get("ea") is not None else "",
            original=line,
            rewritten=result,
        )
    return result


def infer_memory_size_keyword(original_entry, current_dst):
    """Infer the required `ptr` size for a memory-destination rewrite."""
    if not original_entry:
        return None

    wanted = normalize_mem_operand(current_dst)
    matched_sizes = []
    for info in original_entry.get("operand_infos") or []:
        size_keyword = info.get("size_keyword")
        if not size_keyword:
            continue
        candidates = set()
        normalized = info.get("normalized")
        if normalized:
            candidates.add(normalized)
        normalized_asm = info.get("normalized_asm")
        if normalized_asm:
            candidates.add(normalized_asm)
        asm_operand = info.get("asm_operand")
        if asm_operand:
            candidates.add(normalize_mem_operand(asm_operand))
        if wanted in candidates:
            matched_sizes.append(size_keyword)

    unique_sizes = []
    seen_sizes = set()
    for size_keyword in matched_sizes:
        if size_keyword in seen_sizes:
            continue
        seen_sizes.add(size_keyword)
        unique_sizes.append(size_keyword)
    if len(unique_sizes) == 1:
        return unique_sizes[0]

    original_asm = original_entry.get("asm", "")
    _, ops = split_operands(original_asm)
    if not ops:
        return unique_sizes[0] if unique_sizes else None
    mem_ops = [op for op in ops if "[" in op and "]" in op]
    if not mem_ops:
        return unique_sizes[0] if unique_sizes else None

    chosen = None
    for op in mem_ops:
        if normalize_mem_operand(op) == wanted:
            chosen = op
            break
    if chosen is None and len(mem_ops) == 1:
        chosen = mem_ops[0]
    if chosen is None:
        return None

    explicit = infer_operand_size_keyword(chosen)
    if explicit:
        return explicit

    for op in ops:
        if op == chosen:
            continue
        inferred = infer_operand_size_keyword(op)
        if inferred:
            return inferred

    mnem = extract_mnemonic(original_asm)
    if mnem in ("movaps", "movups", "movdqa", "movdqu", "pxor", "xorps"):
        return "xmmword"
    return unique_sizes[0] if unique_sizes else None


def strip_symbol_operand_prefixes(text):
    """Normalize a simple code/data operand before trying IDA name resolution."""
    value = (text or "").strip()
    if not value:
        return ""
    value = re.sub(r"(?i)\b(offset|short|near|far|ptr|large|rel)\b", " ", value)
    value = " ".join(value.split())
    if ":" in value and "[" not in value and "]" not in value:
        value = value.split(":", 1)[1].strip()
    return value


def resolve_symbol_operand_ea(text, arch_key):
    """Resolve a simple symbol-like operand to an EA when possible."""
    operand = strip_symbol_operand_prefixes(text)
    if not operand:
        return None
    if any(ch in operand for ch in "[]()*"):
        return None
    if is_immediate_literal(operand):
        return None
    if _register_hint(operand, arch_key):
        return None
    ea = idc.get_name_ea_simple(operand)
    if ea != ida_idaapi.BADADDR:
        return ea

    for op in ("+", "-"):
        if op not in operand:
            continue
        base_text, offset_text = operand.rsplit(op, 1)
        base_text = base_text.strip()
        offset_text = offset_text.strip()
        if not base_text or not offset_text or not is_immediate_literal(offset_text):
            continue
        if _register_hint(base_text, arch_key):
            continue
        base_ea = idc.get_name_ea_simple(base_text)
        if base_ea == ida_idaapi.BADADDR:
            continue
        offset_value = parse_immediate_value(offset_text)
        if offset_value is None:
            continue
        return base_ea + offset_value if op == "+" else base_ea - offset_value

    return None


def resolve_direct_branch_target_ea(text, arch_key):
    """Resolve a direct `call/jmp` operand into an absolute EA when possible."""
    target_ea = resolve_symbol_operand_ea(text, arch_key)
    if target_ea is not None:
        return target_ea

    operand = strip_symbol_operand_prefixes(text)
    if not operand:
        return None
    if any(ch in operand for ch in "[]()*"):
        return None
    if _register_hint(operand, arch_key):
        return None
    return parse_immediate_value(operand)


def encode_rel32_branch(ea, mnem, target_ea, arch_key):
    """Encode a direct x86/x64 `call/jmp` as rel32 without using an assembler."""
    if arch_key != "x86/x64" or mnem not in ("call", "jmp") or target_ea is None:
        return None

    rel = int(target_ea) - int(ea + 5)
    if rel < -0x80000000 or rel > 0x7FFFFFFF:
        return None

    opcode = 0xE8 if mnem == "call" else 0xE9
    return bytes((opcode,)) + struct.pack("<i", rel)


def assemble_direct_branch_bytes(ea, text, arch_key):
    """Fallback to manual rel32 encoding for simple direct `call/jmp` targets."""
    mnem, operands = split_operands(text)
    if len(operands) < 1:
        return None, None

    target_ea = resolve_direct_branch_target_ea(operands[0], arch_key)
    branch_bytes = encode_rel32_branch(ea, mnem, target_ea, arch_key)
    if branch_bytes is None:
        return None, None

    return (
        branch_bytes,
        "兼容模板: 直接按 rel32 计算 `%s` 目标位移并编码，绕过汇编器的符号解析限制。"
        % mnem,
    )


def is_64bit_program():
    """Return whether the current database is 64-bit."""
    return bool(idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT)


def build_rip_relative_lea_candidate(ea, dst, target_ea, arch_key):
    """Build a position-independent `lea reg, [rip+disp]` candidate for x64."""
    if arch_key != "x86/x64" or not is_64bit_program():
        return None

    from .assemble import try_assemble_line, try_assemble_line_keystone

    dst = (dst or "").strip()
    if not dst:
        return None

    probe = "lea %s, [rip]" % dst
    probe_bytes = try_assemble_line_keystone(ea, probe, arch_key) or try_assemble_line(ea, probe)
    if not probe_bytes:
        probe = "lea %s, [rip+0]" % dst
        probe_bytes = try_assemble_line_keystone(ea, probe, arch_key) or try_assemble_line(ea, probe)
    if not probe_bytes:
        return None

    disp = target_ea - (ea + len(probe_bytes))
    if disp < -0x80000000 or disp > 0x7FFFFFFF:
        return None

    if disp == 0:
        return "lea %s, [rip]" % dst
    if disp > 0:
        return "lea %s, [rip+0x%X]" % (dst, disp)
    return "lea %s, [rip-0x%X]" % (dst, -disp)


def canonical_x64_reg(text):
    """Map partial x64 register views back to their 64-bit canonical register."""
    reg = text.strip().lower()
    mapping = {
        "rax": "rax", "eax": "rax", "ax": "rax", "ah": "rax", "al": "rax",
        "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bh": "rbx", "bl": "rbx",
        "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "ch": "rcx", "cl": "rcx",
        "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dh": "rdx", "dl": "rdx",
        "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
        "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
        "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    }
    if reg in mapping:
        return mapping[reg]
    m = re.fullmatch(r"r(1[0-5]|[8-9])(?:d|w|b)?", reg)
    if m:
        return "r%s" % m.group(1)
    return None


def to_x64_reg32(text):
    """Map an x64 register to its 32-bit form for shorter rewrite templates."""
    base = canonical_x64_reg(text)
    if not base:
        return None
    mapping = {
        "rax": "eax",
        "rbx": "ebx",
        "rcx": "ecx",
        "rdx": "edx",
        "rsi": "esi",
        "rdi": "edi",
        "rbp": "ebp",
        "rsp": "esp",
    }
    if base in mapping:
        return mapping[base]
    m = re.fullmatch(r"r(1[0-5]|[8-9])", base)
    if m:
        return "r%sd" % m.group(1)
    return None


def fallback_assembly_candidates(ea, line, arch_key, original_entry=None):
    """Generate compatibility rewrites when the original text may fail to assemble."""
    mnem, operands = split_operands(line)
    if not mnem:
        return []

    candidates = []
    if arch_key == "x86/x64" and len(operands) >= 1 and mnem in ("call", "jmp"):
        target_ea = resolve_symbol_operand_ea(operands[0], arch_key)
        if target_ea is not None:
            candidates.append(
                (
                    "%s 0x%X" % (mnem, target_ea),
                    "兼容模板: 将 `%s` 的符号目标改写成绝对地址，避免在代码洞里解析失败。"
                    % mnem,
                )
            )

    if arch_key == "x86/x64" and mnem == "lea" and len(operands) >= 2:
        target_ea = resolve_symbol_operand_ea(operands[1], arch_key)
        if target_ea is not None:
            rip_candidate = build_rip_relative_lea_candidate(ea, operands[0], target_ea, arch_key)
            if rip_candidate:
                candidates.append(
                    (
                        rip_candidate,
                        "兼容模板: 将 `lea reg, symbol` 改写成 RIP 相对寻址，避免文件补丁在 ASLR 下失效。"
                    )
                )
            elif not is_64bit_program():
                candidates.append(
                    (
                        "mov %s, 0x%X" % (operands[0], target_ea),
                        "兼容模板: 将 `lea reg, symbol` 改写成地址立即数加载。仅适合不落盘的临时场景。"
                    )
                )

    if arch_key == "x86/x64" and mnem == "mov" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        dst32 = to_x64_reg32(dst)
        value = parse_immediate_value(src)
        if dst32 and value is not None:
            if value == 0:
                candidates.append(
                    (
                        "xor %s, %s" % (dst32, dst32),
                        "兼容模板: 用 `xor %s, %s` 实现清零。"
                        % (dst32, dst32),
                    )
                )
                candidates.append(
                    (
                        "mov %s, 0" % dst32,
                        "兼容模板: 用 `mov %s, 0` 代替 64 位立即数写法。"
                        % dst32,
                    )
                )
            elif 0 <= value <= 0xFFFFFFFF:
                candidates.append(
                    (
                        "mov %s, %s" % (dst32, src),
                        "兼容模板: 用 `mov %s, %s` 代替，它会清零高 32 位。"
                        % (dst32, src),
                    )
                )
        if "[" in dst and "]" in dst and is_immediate_literal(src):
            size_kw = infer_memory_size_keyword(original_entry, dst)
            if size_kw in ("byte", "word", "dword", "qword"):
                dst_clean = strip_size_prefix(dst)
                candidates.append(
                    (
                        "mov %s ptr %s, %s" % (size_kw, dst_clean, src),
                        "兼容模板: 对内存写立即数时自动补上 `%s ptr` 大小限定。"
                        % size_kw,
                    )
                )

    if (
        arch_key == "x86/x64"
        and mnem in ("add", "sub", "and", "or", "xor", "adc", "sbb", "cmp")
        and len(operands) >= 2
    ):
        dst, src = operands[0], operands[1]
        if "[" in dst and "]" in dst and is_immediate_literal(src):
            size_kw = infer_memory_size_keyword(original_entry, dst)
            if size_kw in ("byte", "word", "dword", "qword"):
                dst_clean = strip_size_prefix(dst)
                candidates.append(
                    (
                        "%s %s ptr %s, %s" % (mnem, size_kw, dst_clean, src),
                        "兼容模板: 对内存做 `%s imm` 时自动补上 `%s ptr` 大小限定。"
                        % (mnem, size_kw),
                    )
                )

    if arch_key == "x86/x64" and mnem in ("movaps", "movups", "movdqa", "movdqu") and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        scalar_size = infer_operand_size_keyword(dst)
        if "[" in dst and "]" in dst and scalar_size in ("byte", "word", "dword", "qword") and is_immediate_literal(src):
            dst_clean = strip_size_prefix(dst)
            candidates.append(
                (
                    "mov %s ptr %s, %s" % (scalar_size, dst_clean, src),
                    "兼容模板: `%s` 不能直接把立即数写入内存，已按标量 `mov %s ptr` 重写。"
                    % (mnem, scalar_size),
                )
            )
    return candidates
