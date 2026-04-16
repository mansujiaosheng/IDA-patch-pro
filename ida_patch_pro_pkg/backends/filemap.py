"""EA <-> file offset helpers and file chunk writers."""

import os

import ida_idaapi
import ida_loader
import ida_segment

from ..constants import PATCH_FILE_SECTION_NAME, PATCH_STUB_ALIGN
from ..ida_adapter import segment_name
from ..logging_utils import debug_log


# 缓存 ELF 文件解析结果
_elf_cache = {}


def invalidate_elf_filemap_cache(path=None):
    """Drop cached ELF parse results after the input file layout changes."""
    if path:
        _elf_cache.pop(path, None)
    else:
        _elf_cache.clear()


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
        # 直接计算补丁段的文件偏移，不依赖后端函数
        # 补丁段的文件偏移 = 段起始地址对应的文件偏移 + (当前EA - 段起始地址)
        seg_start = seg.start_ea
        seg_end = seg.end_ea
        
        # 检查当前EA是否在补丁段范围内
        if seg_start <= ea < seg_end:
            # 尝试从段的注释中获取raw_ptr信息
            cmt = ida_segment.get_segment_cmt(seg, 0)
            if cmt:
                import re
                match = re.search(r'raw_ptr=(0x[0-9a-fA-F]+)', cmt)
                if match:
                    raw_ptr = int(match.group(1), 16)
                    file_offset = raw_ptr + (ea - seg_start)
                    debug_log(
                        "fileregion.fallback",
                        ea="0x%X" % ea,
                        file_offset="0x%X" % file_offset,
                        section=PATCH_FILE_SECTION_NAME,
                        method="comment",
                        seg_start="0x%X" % seg_start,
                        raw_ptr="0x%X" % raw_ptr
                    )
                    return file_offset
            
            # 尝试直接解析 ELF 文件，计算补丁段的起始地址和大小
            try:
                import os
                from .elf_backend import open_input_elf, _parse_ehdr, _parse_phdrs
                data, path = open_input_elf()
                
                # 检查缓存
                if path not in _elf_cache:
                    ehdr = _parse_ehdr(data)
                    phdrs, _, _ = _parse_phdrs(data, ehdr)
                    _elf_cache[path] = (ehdr, phdrs)
                else:
                    ehdr, phdrs = _elf_cache[path]
                
                # 找到最后一个PT_LOAD段
                load_segments = [phdr for phdr in phdrs if phdr["p_type"] == 1]  # PT_LOAD
                if load_segments:
                    target = max(load_segments, key=lambda item: (item["p_offset"] + item["p_filesz"], item["p_vaddr"] + item["p_memsz"]))
                    
                    # 计算补丁段的起始地址和大小
                    bss_gap = max(0, int(target["p_memsz"]) - int(target["p_filesz"]))
                    from ..ida_adapter import current_imagebase
                    mem_end_ea = current_imagebase() + int(target["p_vaddr"]) + int(target["p_memsz"])
                    ea_start = ((mem_end_ea + PATCH_STUB_ALIGN - 1) // PATCH_STUB_ALIGN) * PATCH_STUB_ALIGN
                    align_pad = ea_start - mem_end_ea
                    raw_ptr = int(target["p_offset"]) + int(target["p_filesz"]) + bss_gap + align_pad
                    
                    # 计算当前EA的文件偏移
                    # 不检查范围，直接计算，因为补丁段可能被扩展
                    file_offset = raw_ptr + (ea - ea_start)
                    debug_log(
                        "fileregion.fallback",
                        ea="0x%X" % ea,
                        file_offset="0x%X" % file_offset,
                        section=PATCH_FILE_SECTION_NAME,
                        method="elf_calc",
                        ea_start="0x%X" % ea_start,
                        raw_ptr="0x%X" % raw_ptr
                    )
                    return file_offset
            except Exception as e:
                debug_log(
                    "fileregion.fallback.error",
                    error=str(e),
                    section=PATCH_FILE_SECTION_NAME
                )
            
            # 尝试从PE后端获取信息
            try:
                from .pe_backend import pe_patch_section_info
                info = pe_patch_section_info(0)
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
                            method="pe"
                        )
                        return file_offset
            except Exception:
                pass
    return None


def build_file_patch_chunks(ea, patch_bytes):
    """Convert an EA-based patch into file write chunks."""
    if not patch_bytes:
        return []

    chunks = []
    chunk_offset = None
    chunk = bytearray()

    # 只调用一次 ea_file_offset 获取起始地址的文件偏移
    start_file_offset = ea_file_offset(ea)
    if start_file_offset is None:
        raise RuntimeError("地址 0x%X 不映射到输入文件，无法写回文件。" % ea)

    for index, value in enumerate(patch_bytes):
        # 根据起始偏移和索引计算当前字节的文件偏移
        file_offset = start_file_offset + index
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
