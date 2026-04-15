"""Assembler backends, Keystone fallback, and multiline assembly."""

import glob
import os
import re
import shutil
import subprocess
import sys

import idautils
import idc

from ..data import _register_hint
from ..logging_utils import debug_log
from .operands import normalize_hex_suffix_literals, sanitize_asm_line, split_operands
from .rewrite import assemble_direct_branch_bytes, fallback_assembly_candidates, rewrite_line_for_assembly


def try_assemble_line(ea, text):
    """Try assembling one line with IDA's built-in assembler."""
    prev_batch = idc.batch(1)
    try:
        ok, result = idautils.Assemble(ea, text)
    finally:
        idc.batch(prev_batch)

    if ok:
        return bytes(result)
    return None


def can_try_keystone_on_line(text, arch_key):
    """Check whether a line is simple enough for Keystone fallback assembly."""
    if arch_key != "x86/x64":
        return False

    mnem, operands = split_operands(text)
    if not mnem:
        return False

    allowed_words = {
        "byte",
        "word",
        "dword",
        "qword",
        "xmmword",
        "ymmword",
        "zmmword",
        "tbyte",
        "ptr",
        "short",
        "near",
        "far",
    }

    for operand in operands:
        scan = operand.lower()
        scan = re.sub(r"(?i)\b0x[0-9a-f]+\b", " ", scan)
        scan = re.sub(r"(?i)\b[0-9][0-9a-f]*h\b", " ", scan)
        scan = re.sub(r"\b\d+\b", " ", scan)
        for token in re.findall(r"\$[a-z_][a-z0-9_]*|[a-z_][a-z0-9_]*", scan):
            if token in allowed_words:
                continue
            if _register_hint(token, arch_key):
                continue
            return False
    return True


def load_keystone_module():
    """Import Keystone from IDA Python or common Windows Python installs."""
    try:
        import keystone  # type: ignore

        return keystone
    except Exception:
        pass

    candidates = []

    def add_dir(path):
        if not path:
            return
        path = os.path.normpath(path)
        if os.path.isdir(path) and path not in candidates:
            candidates.append(path)

    exe = sys.executable or ""
    if exe:
        add_dir(os.path.join(os.path.dirname(exe), "Lib", "site-packages"))

    for env_name in ("LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name)
        if not base:
            continue
        for root in glob.glob(os.path.join(base, "Python*")):
            add_dir(os.path.join(root, "Lib", "site-packages"))
        for root in glob.glob(os.path.join(base, "Programs", "Python", "Python*")):
            add_dir(os.path.join(root, "Lib", "site-packages"))

    for path in candidates:
        if path not in sys.path:
            sys.path.append(path)
        try:
            import keystone  # type: ignore

            return keystone
        except Exception:
            continue

    return None


def try_assemble_line_keystone(ea, text, arch_key):
    """Try assembling one line with Keystone, locally or via system Python."""
    if not can_try_keystone_on_line(text, arch_key):
        return None

    keystone = load_keystone_module()
    if keystone is not None:
        try:
            mode = keystone.KS_MODE_64 if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else keystone.KS_MODE_32
            ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
            encoded, _ = ks.asm(text, addr=ea, as_bytes=True)
            if encoded:
                return bytes(encoded)
        except Exception:
            pass

    mode_name = "64" if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else "32"
    helper = (
        "import sys\n"
        "from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64\n"
        "mode = KS_MODE_64 if sys.argv[1] == '64' else KS_MODE_32\n"
        "ks = Ks(KS_ARCH_X86, mode)\n"
        "enc, _ = ks.asm(sys.argv[3], addr=int(sys.argv[2], 0), as_bytes=True)\n"
        "print(bytes(enc).hex())\n"
    )
    for launcher in (["python"], ["py", "-3"]):
        if shutil.which(launcher[0]) is None:
            continue
        try:
            proc = subprocess.run(
                launcher + ["-c", helper, mode_name, hex(ea), text],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            continue

        if proc.returncode != 0:
            continue

        hex_text = (proc.stdout or "").strip()
        if not hex_text:
            continue
        try:
            return bytes.fromhex(hex_text)
        except ValueError:
            continue

    return None


def assemble_bytes(ea, text, arch_key, original_entry=None, log_events=True):
    """Assemble one line after trying rewritten text and compatibility fallbacks."""
    rewritten = rewrite_line_for_assembly(text, arch_key, original_entry, log_events=log_events)
    prepared = normalize_hex_suffix_literals(rewritten)
    prepared_note = None
    note_parts = []
    if rewritten != text:
        note_parts.append("自动将栈变量表达式折算为真实偏移后汇编。")
    if normalize_hex_suffix_literals(rewritten) != rewritten:
        note_parts.append("同时规范化了 `...h` 立即数字面量。")
    if note_parts:
        prepared_note = " ".join(note_parts)

    attempts = []
    seen = set()
    if prepared not in seen:
        attempts.append((prepared, prepared_note))
        seen.add(prepared)

    for candidate, note in fallback_assembly_candidates(ea, prepared, arch_key, original_entry):
        candidate = normalize_hex_suffix_literals(
            rewrite_line_for_assembly(candidate, arch_key, original_entry, log_events=log_events)
        )
        if candidate in seen:
            continue
        merged_note = note
        if prepared_note:
            merged_note = (
                prepared_note
                if not note
                else "%s %s" % (prepared_note, note)
            )
        attempts.append((candidate, merged_note))
        seen.add(candidate)

    if text not in seen:
        normalized_text = normalize_hex_suffix_literals(text)
        if normalized_text not in seen:
            attempts.append((normalized_text, None))
            seen.add(normalized_text)

    for candidate, note in attempts:
        buf = try_assemble_line_keystone(ea, candidate, arch_key)
        if buf is not None:
            if log_events:
                debug_log(
                    "assemble_line.success",
                    assembler="keystone",
                    ea="0x%X" % ea,
                    original=text,
                    assembled=candidate,
                    note=note,
                    bytes=buf,
                )
            if note:
                return buf, "%s 使用 Keystone 兼容汇编。" % note
            return buf, "使用 Keystone 兼容汇编。"

    for candidate, note in attempts:
        buf = try_assemble_line(ea, candidate)
        if buf is not None:
            if log_events:
                debug_log(
                    "assemble_line.success",
                    assembler="ida",
                    ea="0x%X" % ea,
                    original=text,
                    assembled=candidate,
                    note=note,
                    bytes=buf,
                )
            return buf, note

    buf, note = assemble_direct_branch_bytes(ea, prepared, arch_key)
    if buf is not None:
        merged_note = note
        if prepared_note:
            merged_note = "%s %s" % (prepared_note, note)
        if log_events:
            debug_log(
                "assemble_line.success",
                assembler="manual_rel32",
                ea="0x%X" % ea,
                original=text,
                assembled=prepared,
                note=merged_note,
                bytes=buf,
            )
        return buf, merged_note

    if log_events:
        debug_log(
            "assemble_line.failure",
            ea="0x%X" % ea,
            original=text,
            attempts=" || ".join(candidate for candidate, _ in attempts),
        )
    raise RuntimeError("无法汇编: %s" % text)


def assemble_multiline(ea, text, arch_key, original_entries=None, log_events=True):
    """Assemble multiple lines and preserve per-line preview metadata."""
    chunks = []
    notes = []
    line_infos = []
    current_ea = ea
    lines = [sanitize_asm_line(line) for line in text.splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        raise RuntimeError("请输入至少一条汇编指令。")

    for index, line in enumerate(lines):
        original_entry = (
            original_entries[index]
            if original_entries is not None and index < len(original_entries)
            else None
        )
        chunk, note = assemble_bytes(
            current_ea,
            line,
            arch_key,
            original_entry,
            log_events=log_events,
        )
        chunks.append(chunk)
        if note:
            notes.append(note)
        line_infos.append({"line": line, "bytes": chunk, "note": note})
        current_ea += len(chunk)
    return b"".join(chunks), notes, line_infos
