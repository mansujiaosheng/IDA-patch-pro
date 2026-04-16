"""PE file backend for .patchf section management."""

import os
import struct

import ida_bytes
import ida_diskio
import ida_loader
import ida_segment

from ..constants import PATCH_FILE_SECTION_NAME, PATCH_SEGMENT_CLASS, PE_SECTION_CHARACTERISTICS_RX
from ..ida_adapter import (
    add_segm_ex_compat,
    current_imagebase,
    find_segment_by_name,
    input_file_path,
    is_64bit_database,
    load_pefile_module,
    read_file_bytes,
    segment_bitness_code,
    segment_name,
)
from ..logging_utils import debug_log


def open_input_pe():
    """Open the current input file as a PE image and return `(module, pe, path)`."""
    path = input_file_path()
    if not path or not os.path.isfile(path):
        raise RuntimeError("当前数据库没有可写回的输入文件。")

    pefile = load_pefile_module()
    if pefile is None:
        raise RuntimeError("未找到 pefile。请在 IDA Python 或系统 Python 中安装。")

    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as exc:
        raise RuntimeError("无法解析输入文件为 PE: %s" % exc)

    return pefile, pe, path


def pe_section_name(section):
    """Return a PE section name as text."""
    try:
        return section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
    except Exception:
        return ""


def pe_header_room_end(pe):
    """Return the end offset of the PE headers area available for section headers."""
    return pe.OPTIONAL_HEADER.SizeOfHeaders


def pe_last_raw_end(pe):
    """Return the highest raw file end among all sections."""
    values = [section.PointerToRawData + section.SizeOfRawData for section in pe.sections]
    return max(values) if values else pe.OPTIONAL_HEADER.SizeOfHeaders


def pe_last_virtual_end(pe):
    """Return the highest RVA end among all sections."""
    values = [
        section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData)
        for section in pe.sections
    ]
    return max(values) if values else pe.OPTIONAL_HEADER.SizeOfHeaders


def pe_patch_section_info(required_size=0):
    """Describe the `.patchf` PE section, creating metadata for extend/create logic."""
    _pefile, pe, path = open_input_pe()
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    imagebase = current_imagebase()

    existing = None
    for section in pe.sections:
        if pe_section_name(section) == PATCH_FILE_SECTION_NAME:
            existing = section
            break

    if existing is not None:
        raw_size = max(existing.SizeOfRawData, required_size)
        raw_size = ((raw_size + file_alignment - 1) // file_alignment) * file_alignment
        virtual_size = max(existing.Misc_VirtualSize, required_size)
        virtual_size = max(virtual_size, existing.SizeOfRawData)
        return {
            "exists": True,
            "path": path,
            "pe": pe,
            "section": existing,
            "section_name": PATCH_FILE_SECTION_NAME,
            "header_offset": existing.get_file_offset(),
            "raw_ptr": existing.PointerToRawData,
            "raw_size": raw_size,
            "virtual_size": virtual_size,
            "virtual_address": existing.VirtualAddress,
            "characteristics": existing.Characteristics,
            "file_alignment": file_alignment,
            "section_alignment": section_alignment,
            "ea_start": imagebase + existing.VirtualAddress,
            "num_sections_offset": pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"),
            "size_image_offset": pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
            "size_code_offset": pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfCode"),
            "can_add": True,
        }

    new_raw_ptr = ((pe_last_raw_end(pe) + file_alignment - 1) // file_alignment) * file_alignment
    new_virtual_address = ((pe_last_virtual_end(pe) + section_alignment - 1) // section_alignment) * section_alignment
    new_raw_size = ((max(required_size, file_alignment) + file_alignment - 1) // file_alignment) * file_alignment
    new_virtual_size = max(required_size, new_raw_size)
    last_header_offset = pe.sections[-1].get_file_offset() if pe.sections else (
        pe.DOS_HEADER.e_lfanew
        + 4
        + struct.calcsize(pe.FILE_HEADER.__format_str__)
        + pe.FILE_HEADER.SizeOfOptionalHeader
    )
    new_header_offset = last_header_offset + 40

    return {
        "exists": False,
        "path": path,
        "pe": pe,
        "section": None,
        "section_name": PATCH_FILE_SECTION_NAME,
        "header_offset": new_header_offset,
        "raw_ptr": new_raw_ptr,
        "raw_size": new_raw_size,
        "virtual_size": new_virtual_size,
        "virtual_address": new_virtual_address,
        "characteristics": PE_SECTION_CHARACTERISTICS_RX,
        "file_alignment": file_alignment,
        "section_alignment": section_alignment,
        "ea_start": imagebase + new_virtual_address,
        "num_sections_offset": pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"),
        "size_image_offset": pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
        "size_code_offset": pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfCode"),
        "can_add": (new_header_offset + 40) <= pe_header_room_end(pe),
    }


def write_zero_fill(fh, start_offset, end_offset):
    """Write zeros to fill a file gap."""
    if end_offset <= start_offset:
        return
    fh.seek(start_offset)
    fh.write(b"\x00" * (end_offset - start_offset))


def ensure_file_length(path, end_offset):
    """Extend the file with zeros up to `end_offset` bytes."""
    current_size = os.path.getsize(path)
    if current_size >= end_offset:
        return
    with open(path, "r+b") as fh:
        write_zero_fill(fh, current_size, end_offset)


def create_pe_patch_section(required_size):
    """Create a dedicated executable PE section for file-backed trampolines."""
    info = pe_patch_section_info(required_size)
    if info["exists"]:
        return info
    if not info["can_add"]:
        raise RuntimeError("PE 头部没有足够空间新增 `%s` 节。" % info["section_name"])

    path = info["path"]
    section_name = info["section_name"].encode("ascii", errors="ignore")[:8].ljust(8, b"\x00")
    end_offset = info["raw_ptr"] + info["raw_size"]
    ensure_file_length(path, end_offset)

    with open(path, "r+b") as fh:
        fh.seek(info["header_offset"])
        fh.write(
            struct.pack(
                "<8sIIIIIIHHI",
                section_name,
                info["virtual_size"],
                info["virtual_address"],
                info["raw_size"],
                info["raw_ptr"],
                0,
                0,
                0,
                0,
                info["characteristics"],
            )
        )
        fh.seek(info["num_sections_offset"])
        fh.write(struct.pack("<H", info["pe"].FILE_HEADER.NumberOfSections + 1))
        fh.seek(info["size_image_offset"])
        new_size_image = info["virtual_address"] + (
            ((info["virtual_size"] + info["section_alignment"] - 1) // info["section_alignment"])
            * info["section_alignment"]
        )
        fh.write(struct.pack("<I", new_size_image))
        if info["size_code_offset"] is not None:
            fh.seek(info["size_code_offset"])
            fh.write(struct.pack("<I", info["pe"].OPTIONAL_HEADER.SizeOfCode + info["raw_size"]))

    debug_log(
        "pe_patch_section.create",
        path=path,
        section=info["section_name"],
        raw_ptr="0x%X" % info["raw_ptr"],
        raw_size="0x%X" % info["raw_size"],
        rva="0x%X" % info["virtual_address"],
    )
    return pe_patch_section_info(required_size)


def extend_pe_patch_section(required_size):
    """Extend an existing PE patch section to fit more cave bytes."""
    info = pe_patch_section_info(required_size)
    if not info["exists"]:
        return create_pe_patch_section(required_size)

    new_raw_size = ((max(required_size, info["raw_size"]) + info["file_alignment"] - 1) // info["file_alignment"]) * info["file_alignment"]
    if new_raw_size <= info["section"].SizeOfRawData:
        return info

    path = info["path"]
    end_offset = info["raw_ptr"] + new_raw_size
    ensure_file_length(path, end_offset)

    with open(path, "r+b") as fh:
        fh.seek(info["section"].get_field_absolute_offset("Misc_VirtualSize"))
        fh.write(struct.pack("<I", max(info["virtual_size"], required_size)))
        fh.seek(info["section"].get_field_absolute_offset("SizeOfRawData"))
        fh.write(struct.pack("<I", new_raw_size))
        fh.seek(info["section"].get_field_absolute_offset("Characteristics"))
        fh.write(struct.pack("<I", info["characteristics"]))
        fh.seek(info["size_image_offset"])
        new_size_image = info["virtual_address"] + (
            ((max(info["virtual_size"], required_size) + info["section_alignment"] - 1) // info["section_alignment"])
            * info["section_alignment"]
        )
        fh.write(struct.pack("<I", new_size_image))
        if info["size_code_offset"] is not None:
            fh.seek(info["size_code_offset"])
            fh.write(struct.pack("<I", info["pe"].OPTIONAL_HEADER.SizeOfCode + (new_raw_size - info["section"].SizeOfRawData)))

    debug_log(
        "pe_patch_section.extend",
        path=path,
        section=info["section_name"],
        old_raw_size="0x%X" % info["section"].SizeOfRawData,
        new_raw_size="0x%X" % new_raw_size,
    )
    return pe_patch_section_info(required_size)


def segment_perms_from_chars(characteristics):
    """Map PE section flags to IDA segment permissions."""
    perms = ida_segment.SEGPERM_READ
    if characteristics & 0x20000000:
        perms |= ida_segment.SEGPERM_EXEC
    if characteristics & 0x80000000:
        perms |= ida_segment.SEGPERM_WRITE
    return perms


def sync_file_patch_segment_to_idb(info):
    """Create or resize the IDA segment that mirrors the PE patch section."""
    seg = ida_segment.getseg(info["ea_start"])
    if seg is None:
        if not add_segm_ex_compat(
            info["ea_start"],
            info["ea_start"] + info["raw_size"],
            0,
            segment_bitness_code(),
            ida_segment.saRelByte,
            ida_segment.scPub,
            ida_segment.ADDSEG_QUIET | ida_segment.ADDSEG_NOSREG | ida_segment.ADDSEG_NOTRUNC,
        ):
            raise RuntimeError("无法在 IDA 中创建文件补丁节段 `%s`。" % info["section_name"])
        seg = ida_segment.getseg(info["ea_start"])
    elif seg.end_ea < info["ea_start"] + info["raw_size"]:
        if not ida_segment.set_segm_end(
            seg.start_ea,
            info["ea_start"] + info["raw_size"],
            ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT,
        ):
            raise RuntimeError("无法扩展 IDA 中的文件补丁节段 `%s`。" % info["section_name"])
        seg = ida_segment.getseg(info["ea_start"])

    if seg is None:
        raise RuntimeError("文件补丁节段创建后无法重新获取。")

    ida_segment.set_segm_name(seg, info["section_name"])
    ida_segment.set_segm_class(seg, PATCH_SEGMENT_CLASS)
    ida_segment.set_segm_addressing(seg, segment_bitness_code())
    seg.perm = segment_perms_from_chars(info["characteristics"])
    ida_segment.update_segm(seg)
    ida_segment.set_segment_cmt(
        seg,
        "ida_patch_pro file-backed patch section. 此段已同步到输入文件，可直接运行/调试。 raw_ptr=0x%X"
        % info["raw_ptr"],
        0,
    )

    li = ida_diskio.open_linput(info["path"], False)
    if li is None:
        raise RuntimeError("无法打开输入文件以映射补丁节 `%s`。" % info["section_name"])
    try:
        ok = ida_loader.file2base(
            li,
            info["raw_ptr"],
            info["ea_start"],
            info["ea_start"] + info["raw_size"],
            ida_loader.FILEREG_PATCHABLE,
        )
    finally:
        ida_diskio.close_linput(li)

    if not ok:
        raise RuntimeError("无法把文件补丁节 `%s` 映射回 IDA 数据库。" % info["section_name"])

    data = read_file_bytes(info["path"], info["raw_ptr"], info["raw_size"])
    if len(data) != info["raw_size"]:
        raise RuntimeError("无法读取文件补丁节 `%s` 的原始字节。" % info["section_name"])
    ida_bytes.patch_bytes(info["ea_start"], data)
    debug_log(
        "pe_patch_section.sync",
        path=info["path"],
        section=info["section_name"],
        raw_ptr="0x%X" % info["raw_ptr"],
        raw_size="0x%X" % info["raw_size"],
        ea_start="0x%X" % info["ea_start"],
    )
    return seg


def prepare_file_patch_segment(required_size, apply_changes=False):
    """Ensure a PE patch section exists and is mirrored into IDA."""
    from .filemap import ea_file_offset

    info = pe_patch_section_info(required_size)
    if apply_changes:
        if info["exists"]:
            info = extend_pe_patch_section(required_size)
        else:
            info = create_pe_patch_section(required_size)
    elif info["exists"] and find_segment_by_name(
        info["section_name"], file_backed=True, offset_resolver=ea_file_offset
    ) is None:
        info["segment"] = sync_file_patch_segment_to_idb(info)

    if apply_changes or info.get("segment") is not None:
        info["segment"] = sync_file_patch_segment_to_idb(info)
    else:
        info["segment"] = find_segment_by_name(
            info["section_name"], file_backed=True, offset_resolver=ea_file_offset
        )
    return info
