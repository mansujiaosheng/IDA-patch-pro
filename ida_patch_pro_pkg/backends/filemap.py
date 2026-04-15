"""EA <-> file offset helpers and file chunk writers."""

import os

import ida_idaapi
import ida_loader
import ida_segment

from ..constants import PATCH_FILE_SECTION_NAME
from ..ida_adapter import segment_name
from ..logging_utils import debug_log


def ea_file_offset(ea):
    """Map an EA to its file offset, or return None for non-file-backed bytes."""
    try:
        offset = ida_loader.get_fileregion_offset(ea)
    except Exception:
        offset = None
    if offset is not None and offset != ida_idaapi.BADADDR and (not isinstance(offset, int) or offset >= 0):
        return offset

    seg = ida_segment.getseg(ea)
    if seg is not None and segment_name(seg) == PATCH_FILE_SECTION_NAME:
        from .pe_backend import pe_patch_section_info

        try:
            info = pe_patch_section_info(0)
        except Exception:
            info = None
        if info and info.get("exists"):
            start = info["ea_start"]
            end = start + info["raw_size"]
            if start <= ea < end:
                file_offset = info["raw_ptr"] + (ea - start)
                debug_log(
                    "fileregion.fallback",
                    ea="0x%X" % ea,
                    file_offset="0x%X" % file_offset,
                    section=PATCH_FILE_SECTION_NAME,
                )
                return file_offset
    return None


def build_file_patch_chunks(ea, patch_bytes):
    """Convert an EA-based patch into file write chunks."""
    if not patch_bytes:
        return []

    chunks = []
    chunk_offset = None
    chunk = bytearray()

    for index, value in enumerate(patch_bytes):
        file_offset = ea_file_offset(ea + index)
        if file_offset is None:
            raise RuntimeError("地址 0x%X 不映射到输入文件，无法写回文件。" % (ea + index))
        if chunk_offset is None:
            chunk_offset = file_offset
        elif file_offset != chunk_offset + len(chunk):
            chunks.append((chunk_offset, bytes(chunk)))
            chunk_offset = file_offset
            chunk = bytearray()
        chunk.append(value)

    if chunk_offset is not None:
        chunks.append((chunk_offset, bytes(chunk)))
    return chunks


def write_patch_chunks_to_input_file(chunks):
    """Write file patch chunks back to the original input file."""
    if not chunks:
        return ""

    from ..ida_adapter import input_file_path

    path = input_file_path()
    if not path:
        raise RuntimeError("当前数据库没有可写回的输入文件路径。")
    if not os.path.isfile(path):
        raise RuntimeError("输入文件不存在: %s" % path)

    with open(path, "r+b") as fh:
        for offset, data in chunks:
            fh.seek(offset)
            fh.write(data)
    return path
