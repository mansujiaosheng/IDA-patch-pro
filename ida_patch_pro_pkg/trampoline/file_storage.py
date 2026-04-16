"""Format-aware file-backed storage helpers for trampoline code caves."""

import os

from ..constants import PATCH_FILE_SECTION_NAME
from ..ida_adapter import input_file_path, read_file_bytes, segment_name
from ..backends.elf_backend import prepare_elf_patch_segment
from ..backends.pe_backend import prepare_file_patch_segment
from .caves import find_file_code_cave, next_patch_cursor

BINARY_KIND_PE = "pe"
BINARY_KIND_ELF = "elf"
BINARY_KIND_UNKNOWN = "unknown"


def input_binary_kind():
    """Return a coarse file-format kind for the current input file."""
    path = input_file_path()
    ext = os.path.splitext(path or "")[1].lower()

    if path and os.path.isfile(path):
        try:
            magic = read_file_bytes(path, 0, 4)
        except Exception:
            magic = b""
        if magic.startswith(b"MZ"):
            return BINARY_KIND_PE
        if magic.startswith(b"\x7fELF"):
            return BINARY_KIND_ELF

    if ext in (".exe", ".dll", ".pyd"):
        return BINARY_KIND_PE
    if ext in (".elf", ".so"):
        return BINARY_KIND_ELF
    return BINARY_KIND_UNKNOWN


def input_binary_label(kind=None):
    """Return a short user-facing file-format label."""
    kind = kind or input_binary_kind()
    if kind == BINARY_KIND_PE:
        return "PE"
    if kind == BINARY_KIND_ELF:
        return "ELF"
    return "Unknown"


def file_storage_display_text(kind=None):
    """Return one short description of file-backed cave storage."""
    kind = kind or input_binary_kind()
    if kind in (BINARY_KIND_PE, BINARY_KIND_ELF):
        return "输入文件内 `%s` 节" % PATCH_FILE_SECTION_NAME
    return "输入文件内现有可执行代码洞"


def file_storage_behavior_text(kind=None):
    """Return a longer explanation of how file-backed cave storage works."""
    kind = kind or input_binary_kind()
    if kind == BINARY_KIND_PE:
        return "写入输入文件时，会自动创建/扩展 `%s` 节用于放置代码洞。" % PATCH_FILE_SECTION_NAME
    if kind == BINARY_KIND_ELF:
        return "写入输入文件时，会自动扩展最后一个 PT_LOAD，并在其尾部创建/扩展 `%s` 补丁段。" % PATCH_FILE_SECTION_NAME
    return "写入输入文件时，会优先复用输入文件现有可执行代码洞。"


def file_storage_tooltip_text(kind=None):
    """Return tooltip text for the trampoline write-to-file checkbox."""
    kind = kind or input_binary_kind()
    if kind == BINARY_KIND_PE:
        return "勾选后会创建或扩展输入文件中的专用补丁节，并把入口/代码洞都写回输入文件。"
    if kind == BINARY_KIND_ELF:
        return "勾选后会把入口和代码洞写回输入文件，并自动扩展 ELF/so 的最后一个 PT_LOAD 来承载补丁段。"
    return "勾选后会把入口和代码洞写回输入文件，并优先复用现有可执行代码洞。"


def preview_storage_source_text(plan):
    """Return one display string for a planned file-backed cave location."""
    storage_mode = (plan or {}).get("storage_mode")
    if storage_mode == "file_section":
        return "输入文件里的专用补丁节 `%s`" % ((plan or {}).get("segment_name") or PATCH_FILE_SECTION_NAME)
    if storage_mode == "file_cave":
        segment = (plan or {}).get("segment_name") or "(unknown)"
        return "输入文件里的现有可执行代码洞 `%s`" % segment
    return "IDB 专用代码洞"


def prepare_file_trampoline_storage(required_size, preferred_ea=None, apply_changes=False):
    """Prepare one file-backed trampoline storage plan for the current input format."""
    kind = input_binary_kind()
    if kind == BINARY_KIND_PE:
        info = prepare_file_patch_segment(required_size, apply_changes=apply_changes)
        seg = info.get("segment")
        cave_start = next_patch_cursor(seg) if seg is not None else info["ea_start"]
        return {
            "binary_kind": kind,
            "binary_label": input_binary_label(kind),
            "storage_mode": "file_section",
            "storage_text": file_storage_display_text(kind),
            "storage_behavior_text": file_storage_behavior_text(kind),
            "segment": seg,
            "segment_name": info["section_name"],
            "cave_start": cave_start,
            "alloc_base_ea": info["ea_start"],
            "available_size": info["raw_size"],
            "backend_info": info,
        }
    if kind == BINARY_KIND_ELF:
        info = prepare_elf_patch_segment(required_size, apply_changes=apply_changes)
        seg = info.get("segment")
        cave_start = next_patch_cursor(seg) if seg is not None else info["ea_start"]
        return {
            "binary_kind": kind,
            "binary_label": input_binary_label(kind),
            "storage_mode": "file_section",
            "storage_text": file_storage_display_text(kind),
            "storage_behavior_text": file_storage_behavior_text(kind),
            "segment": seg,
            "segment_name": info["section_name"],
            "cave_start": cave_start,
            "alloc_base_ea": info["ea_start"],
            "available_size": info["raw_size"],
            "backend_info": info,
        }

    cave = find_file_code_cave(required_size, preferred_ea=preferred_ea)
    return {
        "binary_kind": kind,
        "binary_label": input_binary_label(kind),
        "storage_mode": "file_cave",
        "storage_text": file_storage_display_text(kind),
        "storage_behavior_text": file_storage_behavior_text(kind),
        "segment": cave["segment"],
        "segment_name": segment_name(cave["segment"]),
        "cave_start": cave["start"],
        "alloc_base_ea": cave["start"],
        "available_size": cave["available_size"],
        "run_start": cave["run_start"],
        "run_end": cave["run_end"],
        "backend_info": cave,
    }
