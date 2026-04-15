"""Operand parsing, normalization, and size inference helpers."""

import re

import ida_bytes
import ida_ua
import idautils
import idc

from ..data import MNEMONIC_HINTS, _register_hint
from ..logging_utils import debug_log


def sanitize_asm_line(text):
    """Strip trailing IDA comments so only pure assembly text remains."""
    text = (text or "").strip()
    if not text:
        return ""

    cut = len(text)
    for marker in (";", "|"):
        index = text.find(marker)
        if index != -1:
            cut = min(cut, index)
    return text[:cut].strip()


def strip_size_prefix(op):
    """Remove `byte ptr`/`dword ptr`-style prefixes from an operand string."""
    return re.sub(
        r"(?i)\b(?:byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte)\s+ptr\b\s*",
        "",
        op.strip(),
    ).strip()


def split_size_prefix(op):
    """Split an operand into explicit size prefix and core operand body."""
    stripped = op.strip()
    m = re.match(
        r"(?is)^((?:byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte)\s+ptr)\s+(.*)$",
        stripped,
    )
    if not m:
        return "", stripped
    return m.group(1), m.group(2).strip()


def normalize_mem_operand(op):
    """Normalize a memory operand so equivalent spellings compare equal."""
    op = strip_size_prefix(op).lower()
    return re.sub(r"\s+", "", op)


def size_keyword_from_size(size):
    """Map a byte width to an assembler size keyword."""
    mapping = {
        1: "byte",
        2: "word",
        4: "dword",
        8: "qword",
        10: "tbyte",
        16: "xmmword",
        32: "ymmword",
        64: "zmmword",
    }
    return mapping.get(size)


def infer_operand_size_keyword(op):
    """Infer operand width keyword such as byte/dword/qword from text."""
    lower = op.strip().lower()
    for prefix in ("byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword", "tbyte"):
        if re.search(r"(?i)\b%s\s+ptr\b" % prefix, lower):
            return prefix

    reg = lower
    if reg in ("al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "bpl", "spl"):
        return "byte"
    if re.fullmatch(r"r(1[0-5]|[8-9])b", reg):
        return "byte"
    if reg in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        return "word"
    if re.fullmatch(r"r(1[0-5]|[8-9])w", reg):
        return "word"
    if reg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        return "dword"
    if re.fullmatch(r"r(1[0-5]|[8-9])d", reg):
        return "dword"
    if reg in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
        return "qword"
    if re.fullmatch(r"r(1[0-5]|[8-9])", reg):
        return "qword"
    if re.fullmatch(r"xmm([0-9]|1[0-5])", reg):
        return "xmmword"
    if re.fullmatch(r"ymm([0-9]|1[0-5])", reg):
        return "ymmword"
    if re.fullmatch(r"zmm([0-9]|1[0-5]|2[0-9]|3[01])", reg):
        return "zmmword"
    return None


def decoded_operand_size_keyword(ea, index, operand_text=""):
    """Try to infer an operand width from the decoded instruction metadata."""
    explicit = infer_operand_size_keyword(operand_text)
    if explicit:
        return explicit

    try:
        insn = idautils.DecodeInstruction(ea)
    except Exception:
        insn = None
    if not insn:
        return None

    op = None
    ops = getattr(insn, "ops", None)
    if ops is not None:
        try:
            if 0 <= index < len(ops):
                op = ops[index]
        except Exception:
            op = None
    if op is None:
        op = getattr(insn, "Op%d" % (index + 1), None)
    if op is None:
        return None

    dtype = getattr(op, "dtype", None)
    if dtype is None:
        dtype = getattr(op, "dtyp", None)
    if dtype is None:
        return None

    try:
        size = ida_ua.get_dtype_size(dtype)
    except Exception:
        size = None

    if not size:
        fallback_sizes = {
            getattr(ida_ua, "dt_byte", None): 1,
            getattr(ida_ua, "dt_word", None): 2,
            getattr(ida_ua, "dt_dword", None): 4,
            getattr(ida_ua, "dt_float", None): 4,
            getattr(ida_ua, "dt_double", None): 8,
            getattr(ida_ua, "dt_qword", None): 8,
            getattr(ida_ua, "dt_byte16", None): 16,
            getattr(ida_ua, "dt_byte32", None): 32,
            getattr(ida_ua, "dt_byte64", None): 64,
            getattr(ida_ua, "dt_tbyte", None): 10,
        }
        size = fallback_sizes.get(dtype)

    return size_keyword_from_size(size)


def pointer_bits():
    """Return the current database pointer width."""
    return 64 if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else 32


def sign_extend(value, bits):
    """Interpret the given integer as a signed value of `bits` width."""
    if value is None:
        return None
    mask = (1 << bits) - 1
    value &= mask
    sign_bit = 1 << (bits - 1)
    if value & sign_bit:
        value -= 1 << bits
    return value


def format_hex_literal(value):
    """Format an integer as IDA-style hexadecimal text."""
    if value == 0:
        return "0"
    digits = "%X" % value
    if digits[0] in "ABCDEF":
        digits = "0" + digits
    return digits + "h"


def is_registerish_mem_term(token, arch_key):
    """Check whether a memory term looks like a register/index component."""
    token = token.strip().lower()
    if not token:
        return False

    token = token.replace(" ", "")
    if token.startswith("-"):
        token = token[1:]
    if "*" in token:
        token = token.split("*", 1)[0]
    if ":" in token:
        token = token.rsplit(":", 1)[-1]

    return _register_hint(token, arch_key) is not None


def rebuild_stack_operand_text(op_text, disp_value, arch_key):
    """Rewrite IDA stack-var text like `[rsp+198h+var_158]` into real offsets."""
    core = strip_size_prefix(op_text)
    m = re.match(r"(?is)^(?P<prefix>[^[]*?)(?P<body>\[[^]]*\])(?P<suffix>.*)$", core)
    if not m:
        return core

    prefix = m.group("prefix").strip()
    body = m.group("body")[1:-1]
    suffix = m.group("suffix").strip()

    parts = []
    for match in re.finditer(r"([+-]?)\s*([^+-]+)", body):
        sign = match.group(1) or "+"
        term = match.group(2).strip()
        if is_registerish_mem_term(term, arch_key):
            parts.append((sign, term))

    disp_bits = 32 if arch_key == "x86/x64" else pointer_bits()
    disp = sign_extend(int(disp_value), disp_bits)
    if disp is None:
        disp = 0

    body_text = ""
    for index, (sign, term) in enumerate(parts):
        if index == 0:
            body_text = term if sign != "-" else "-" + term
        else:
            body_text += ("-" if sign == "-" else "+") + term

    if disp != 0 or not body_text:
        disp_text = format_hex_literal(abs(disp))
        if body_text:
            body_text += ("-" if disp < 0 else "+") + disp_text
        else:
            body_text = ("-" if disp < 0 else "") + disp_text

    result = "[%s]" % body_text
    if prefix:
        result = "%s%s" % (prefix, result)
    if suffix:
        result = "%s%s" % (result, suffix)
    return result


def first_nonempty_line(text):
    """Return the first non-empty line from a multi-line editor string."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def extract_mnemonic(text):
    """Extract the mnemonic from the first meaningful line of assembly text."""
    line = sanitize_asm_line(first_nonempty_line(text))
    if not line:
        return ""
    tokens = line.split()
    if not tokens:
        return ""
    first = tokens[0].lower()
    if first in ("rep", "repe", "repz", "repne", "repnz", "lock") and len(tokens) >= 2:
        second = tokens[1].lower()
        combined = "%s %s" % (first, second)
        if combined in MNEMONIC_HINTS:
            return combined
        if second in MNEMONIC_HINTS:
            return second
        return combined
    return first


def extract_registers(text, arch_key):
    """Extract registers mentioned in the current line for hint display."""
    line = first_nonempty_line(text).lower()
    if not line:
        return []

    found = []
    seen = set()
    for token in re.findall(r"\$[a-z0-9]+|[a-z][a-z0-9()]*", line):
        if token in seen:
            continue
        if _register_hint(token, arch_key):
            found.append(token)
            seen.add(token)
    return found


def split_operands(text):
    """Split a single instruction into mnemonic and operand list."""
    line = sanitize_asm_line(first_nonempty_line(text))
    if not line:
        return "", []

    code = line.strip()
    parts = code.split(None, 1)
    if not parts:
        return "", []
    if len(parts) == 1:
        return parts[0].lower(), []

    ops = []
    current = []
    depth = 0
    for ch in parts[1]:
        if ch in "[({":
            depth += 1
        elif ch in "])}" and depth > 0:
            depth -= 1

        if ch == "," and depth == 0:
            operand = "".join(current).strip()
            if operand:
                ops.append(operand)
            current = []
            continue
        current.append(ch)

    operand = "".join(current).strip()
    if operand:
        ops.append(operand)
    return parts[0].lower(), ops


def is_zero_literal(text):
    """Return whether the text represents zero in decimal or hex form."""
    value = text.strip().lower().replace("_", "")
    if not value:
        return False
    if value in ("0", "+0", "-0", "0h", "+0h", "-0h", "0x0", "+0x0", "-0x0"):
        return True
    if value.startswith(("0x", "+0x", "-0x")):
        value = value.replace("+", "").replace("-", "")
        return value[2:] and set(value[2:]) == {"0"}
    if value.endswith("h"):
        value = value[:-1].replace("+", "").replace("-", "")
        return value and set(value) == {"0"}
    return value.replace("+", "").replace("-", "").isdigit() and set(value.replace("+", "").replace("-", "")) == {"0"}


def is_immediate_literal(text):
    """Return whether the text looks like an immediate literal value."""
    value = text.strip().lower().replace("_", "")
    if not value:
        return False
    if value.startswith(("0x", "+0x", "-0x")):
        body = value.replace("+", "").replace("-", "")[2:]
        return bool(body) and all(ch in "0123456789abcdef" for ch in body)
    if value.endswith("h"):
        body = value[:-1].replace("+", "").replace("-", "")
        return bool(body) and all(ch in "0123456789abcdef" for ch in body)
    value = value.replace("+", "").replace("-", "")
    return value.isdigit()


def parse_immediate_value(text):
    """Parse a decimal/hex literal and return its integer value."""
    value = text.strip().lower().replace("_", "")
    if not value:
        return None
    sign = 1
    if value[0] == "+":
        value = value[1:]
    elif value[0] == "-":
        sign = -1
        value = value[1:]
    if not value:
        return None
    try:
        if value.startswith("0x"):
            return sign * int(value, 16)
        if value.endswith("h"):
            return sign * int(value[:-1], 16)
        return sign * int(value, 10)
    except ValueError:
        return None


def normalize_hex_suffix_literals(text):
    """Normalize MASM-style hex literals like `0bh` into a stable assembler form."""
    if not text:
        return text

    def repl(match):
        sign = match.group(1) or ""
        digits = match.group(2) or ""
        return "%s%sh" % (sign, digits.upper())

    return re.sub(
        r"(?i)(?<![0-9A-Za-z_])([+-]?)([0-9][0-9a-f]*)h(?![0-9A-Za-z_])",
        repl,
        text,
    )


def processor_key():
    """Map IDA processor info to the plugin's architecture categories."""
    proc_name = idc.get_inf_attr(idc.INF_PROCNAME)
    is_64bit = bool(idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT)

    if proc_name == "metapc":
        return "x86/x64"
    if proc_name == "ARM":
        return "AArch64" if is_64bit else "ARM/Thumb"
    if proc_name in ("mips", "mipsb", "mipsl"):
        return "MIPS"
    return "x86/x64"


def build_operand_infos(ea, asm):
    """Collect per-operand display text, rewritten forms, and inferred size hints."""
    arch_key = processor_key()
    flags = ida_bytes.get_flags(ea)
    _, operands = split_operands(asm)
    infos = []

    for index, operand in enumerate(operands):
        asm_operand = operand
        if (
            arch_key == "x86/x64"
            and "[" in operand
            and "]" in operand
            and ida_bytes.is_stkvar(flags, index)
        ):
            disp_value = idc.get_operand_value(ea, index)
            asm_operand = rebuild_stack_operand_text(operand, disp_value, arch_key)
        size_keyword = decoded_operand_size_keyword(ea, index, operand)
        infos.append(
            {
                "index": index,
                "display": operand,
                "normalized": normalize_mem_operand(operand),
                "asm_operand": asm_operand,
                "normalized_asm": normalize_mem_operand(asm_operand),
                "size_keyword": size_keyword,
            }
        )
        if asm_operand != operand or size_keyword:
            debug_log(
                "operand_info",
                ea="0x%X" % ea,
                index=index,
                display=operand,
                asm_operand=asm_operand,
                size_keyword=size_keyword,
            )
    return infos
