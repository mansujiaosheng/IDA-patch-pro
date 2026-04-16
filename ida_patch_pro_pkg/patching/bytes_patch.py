"""Byte patch helpers for code/data replacement and NOP fill."""

import ida_auto
import ida_bytes
import ida_kernwin

from ..asm.assemble import assemble_bytes
from ..asm.operands import processor_key
from ..backends.filemap import build_file_patch_chunks, write_patch_chunks_to_input_file
from ..logging_utils import debug_log


def build_nop_bytes(ea, size):
    """Assemble enough NOP instructions to fill the requested byte count."""
    parts = []
    remaining = size
    current_ea = ea
    arch_key = processor_key()

    while remaining > 0:
        nop_bytes, _ = assemble_bytes(current_ea, "nop", arch_key)
        if not nop_bytes:
            raise RuntimeError("NOP 汇编结果为空。")
        if len(nop_bytes) > remaining:
            raise RuntimeError(
                "无法用当前处理器的 NOP 指令精确覆盖地址 0x%X 处的 %d 字节。"
                % (ea, size)
            )
        parts.append(nop_bytes)
        current_ea += len(nop_bytes)
        remaining -= len(nop_bytes)

    return b"".join(parts)


def patch_instruction(ea, patch_bytes):
    """Patch one instruction-sized region and recreate the instruction there."""
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(patch_bytes))
    ida_bytes.patch_bytes(ea, patch_bytes)
    ida_auto.auto_recreate_insn(ea)


def patch_bytes_as_code(ea, patch_bytes):
    """Patch raw bytes and ask IDA to recreate code over the whole range."""
    end_ea = ea + len(patch_bytes)
    delete_flags = getattr(ida_bytes, "DELIT_EXPAND", ida_bytes.DELIT_SIMPLE)
    ida_bytes.del_items(ea, delete_flags, len(patch_bytes))
    ida_bytes.patch_bytes(ea, patch_bytes)

    current = ea
    while current < end_ea:
        length = ida_auto.auto_recreate_insn(current)
        if length <= 0:
            current += 1
        else:
            current += length

    ida_kernwin.refresh_idaview_anyway()


def apply_code_patch(ea, patch_bytes, write_to_file=False):
    """Patch bytes into IDA, and optionally sync them back to the input file."""
    file_path = ""
    if write_to_file:
        chunks = build_file_patch_chunks(ea, patch_bytes)
        file_path = write_patch_chunks_to_input_file(chunks)
        debug_log(
            "input_file.write",
            ea="0x%X" % ea,
            byte_count=len(patch_bytes),
            file_path=file_path,
        )

    patch_bytes_as_code(ea, patch_bytes)
    return file_path
