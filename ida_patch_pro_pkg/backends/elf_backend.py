"""ELF file backend for file-backed trampoline/code-cave storage."""

import os
import struct

import ida_diskio
import ida_loader
import ida_segment
import ida_bytes

from ..constants import PATCH_FILE_SECTION_NAME, PATCH_SEGMENT_CLASS, PATCH_SEGMENT_DEFAULT_SIZE, PATCH_STUB_ALIGN
from ..ida_adapter import (
    add_segm_ex_compat,
    current_imagebase,
    find_segment_by_name,
    input_file_path,
    read_file_bytes,
    segment_bitness_code,
)
from ..logging_utils import debug_log

ELF_MAGIC = b"\x7fELF"
EI_CLASS = 4
EI_DATA = 5
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

PT_LOAD = 1
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4


def align_up(value, alignment):
    """Round a value up to the next multiple of `alignment`."""
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def _elf_kind_from_ident(ident):
    """Return parsed ELF class/data info from e_ident bytes."""
    if len(ident) < 16 or not ident.startswith(ELF_MAGIC):
        raise RuntimeError("当前输入文件不是 ELF。")
    elf_class = ident[EI_CLASS]
    elf_data = ident[EI_DATA]
    if elf_class not in (ELFCLASS32, ELFCLASS64):
        raise RuntimeError("暂不支持该 ELF 位数。")
    if elf_data == ELFDATA2LSB:
        endian = "<"
    elif elf_data == ELFDATA2MSB:
        endian = ">"
    else:
        raise RuntimeError("暂不支持该 ELF 字节序。")
    return elf_class, endian


def _ehdr_format(elf_class):
    """Return struct format for the ELF header."""
    if elf_class == ELFCLASS64:
        return "16sHHIQQQIHHHHHH"
    return "16sHHIIIIIHHHHHH"


def _phdr_format(elf_class):
    """Return struct format for one program header."""
    if elf_class == ELFCLASS64:
        return "IIQQQQQQ"
    return "IIIIIIII"


def _shdr_format(elf_class):
    """Return struct format for one section header."""
    if elf_class == ELFCLASS64:
        return "IIQQQQIIQQ"
    return "IIIIIIIIII"


def _parse_ehdr(data):
    """Parse the ELF header and return a dict with common fields."""
    elf_class, endian = _elf_kind_from_ident(data[:16])
    fmt = endian + _ehdr_format(elf_class)
    values = struct.unpack_from(fmt, data, 0)
    keys = [
        "e_ident",
        "e_type",
        "e_machine",
        "e_version",
        "e_entry",
        "e_phoff",
        "e_shoff",
        "e_flags",
        "e_ehsize",
        "e_phentsize",
        "e_phnum",
        "e_shentsize",
        "e_shnum",
        "e_shstrndx",
    ]
    ehdr = dict(zip(keys, values))
    ehdr["elf_class"] = elf_class
    ehdr["endian"] = endian
    ehdr["ehdr_format"] = fmt
    ehdr["ehdr_size"] = struct.calcsize(fmt)
    if ehdr["e_phnum"] == 0xFFFF or ehdr["e_shnum"] == 0 or ehdr["e_shstrndx"] == 0xFFFF:
        raise RuntimeError("暂不支持包含扩展编号表的 ELF。")
    return ehdr


def _parse_phdrs(data, ehdr):
    """Parse every program header from the ELF file."""
    fmt = ehdr["endian"] + _phdr_format(ehdr["elf_class"])
    size = struct.calcsize(fmt)
    if ehdr["e_phentsize"] != size:
        raise RuntimeError("ELF Program Header 大小不符合预期。")

    phdrs = []
    for index in range(ehdr["e_phnum"]):
        offset = ehdr["e_phoff"] + index * size
        values = struct.unpack_from(fmt, data, offset)
        if ehdr["elf_class"] == ELFCLASS64:
            keys = ["p_type", "p_flags", "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_align"]
        else:
            keys = ["p_type", "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_flags", "p_align"]
        item = dict(zip(keys, values))
        item["index"] = index
        item["offset_in_file"] = offset
        phdrs.append(item)
    return phdrs, fmt, size


def _parse_shdrs(data, ehdr):
    """Parse every section header from the ELF file."""
    if not ehdr["e_shoff"] or not ehdr["e_shnum"]:
        return [], "", 0

    fmt = ehdr["endian"] + _shdr_format(ehdr["elf_class"])
    size = struct.calcsize(fmt)
    if ehdr["e_shentsize"] != size:
        raise RuntimeError("ELF Section Header 大小不符合预期。")

    shdrs = []
    for index in range(ehdr["e_shnum"]):
        offset = ehdr["e_shoff"] + index * size
        values = struct.unpack_from(fmt, data, offset)
        if ehdr["elf_class"] == ELFCLASS64:
            keys = [
                "sh_name",
                "sh_type",
                "sh_flags",
                "sh_addr",
                "sh_offset",
                "sh_size",
                "sh_link",
                "sh_info",
                "sh_addralign",
                "sh_entsize",
            ]
        else:
            keys = [
                "sh_name",
                "sh_type",
                "sh_flags",
                "sh_addr",
                "sh_offset",
                "sh_size",
                "sh_link",
                "sh_info",
                "sh_addralign",
                "sh_entsize",
            ]
        item = dict(zip(keys, values))
        item["index"] = index
        item["offset_in_file"] = offset
        shdrs.append(item)
    return shdrs, fmt, size


def _pack_ehdr(ehdr):
    """Pack an ELF header dict back to bytes."""
    values = [
        ehdr["e_ident"],
        ehdr["e_type"],
        ehdr["e_machine"],
        ehdr["e_version"],
        ehdr["e_entry"],
        ehdr["e_phoff"],
        ehdr["e_shoff"],
        ehdr["e_flags"],
        ehdr["e_ehsize"],
        ehdr["e_phentsize"],
        ehdr["e_phnum"],
        ehdr["e_shentsize"],
        ehdr["e_shnum"],
        ehdr["e_shstrndx"],
    ]
    return struct.pack(ehdr["ehdr_format"], *values)


def _pack_phdr(phdr, elf_class, endian):
    """Pack one program header dict back to bytes."""
    fmt = endian + _phdr_format(elf_class)
    if elf_class == ELFCLASS64:
        values = [
            phdr["p_type"],
            phdr["p_flags"],
            phdr["p_offset"],
            phdr["p_vaddr"],
            phdr["p_paddr"],
            phdr["p_filesz"],
            phdr["p_memsz"],
            phdr["p_align"],
        ]
    else:
        values = [
            phdr["p_type"],
            phdr["p_offset"],
            phdr["p_vaddr"],
            phdr["p_paddr"],
            phdr["p_filesz"],
            phdr["p_memsz"],
            phdr["p_flags"],
            phdr["p_align"],
        ]
    return struct.pack(fmt, *values)


def _pack_shdr(shdr, elf_class, endian):
    """Pack one section header dict back to bytes."""
    fmt = endian + _shdr_format(elf_class)
    values = [
        shdr["sh_name"],
        shdr["sh_type"],
        shdr["sh_flags"],
        shdr["sh_addr"],
        shdr["sh_offset"],
        shdr["sh_size"],
        shdr["sh_link"],
        shdr["sh_info"],
        shdr["sh_addralign"],
        shdr["sh_entsize"],
    ]
    return struct.pack(fmt, *values)


def open_input_elf():
    """Open the current input file as raw ELF bytes."""
    path = input_file_path()
    if not path or not os.path.isfile(path):
        raise RuntimeError("当前数据库没有可写回的输入文件。")
    with open(path, "rb") as fh:
        data = fh.read()
    _parse_ehdr(data)
    return bytearray(data), path


def _elf_segment_perms(flags):
    """Map ELF PF_* flags to IDA permissions."""
    perms = 0
    if flags & PF_R:
        perms |= ida_segment.SEGPERM_READ
    if flags & PF_W:
        perms |= ida_segment.SEGPERM_WRITE
    if flags & PF_X:
        perms |= ida_segment.SEGPERM_EXEC
    return perms or ida_segment.SEGPERM_READ


def _current_patch_segment_info():
    """Return current session patch-segment info if already mapped in IDA."""
    from .filemap import ea_file_offset

    seg = find_segment_by_name(PATCH_FILE_SECTION_NAME, file_backed=True, offset_resolver=ea_file_offset)
    if seg is None:
        return None
    raw_ptr = ea_file_offset(seg.start_ea)
    if raw_ptr is None:
        return None
    raw_size = int(seg.end_ea - seg.start_ea)
    path = input_file_path()
    if not path or not os.path.isfile(path):
        return None
    file_size = os.path.getsize(path)
    if raw_ptr < 0 or raw_ptr + raw_size > file_size:
        debug_log(
            "elf_patch_segment.stale_mapping",
            path=path,
            seg_start="0x%X" % int(seg.start_ea),
            seg_end="0x%X" % int(seg.end_ea),
            raw_ptr="0x%X" % int(raw_ptr),
            raw_size="0x%X" % int(raw_size),
            file_size="0x%X" % int(file_size),
        )
        return None
    return {
        "segment": seg,
        "section_name": PATCH_FILE_SECTION_NAME,
        "raw_ptr": raw_ptr,
        "raw_size": raw_size,
        "ea_start": int(seg.start_ea),
        "ea_end": int(seg.end_ea),
    }


def elf_patch_segment_info(required_size=0):
    """Describe the current or planned ELF file-backed patch segment."""
    existing = _current_patch_segment_info()
    if existing is not None:
        info = dict(existing)
        info.update(
            {
                "exists": True,
                "path": input_file_path(),
                "binary_kind": "elf",
                "patch_raw_end": info["raw_ptr"] + info["raw_size"],
                "required_size": required_size,
            }
        )
        return info

    data, path = open_input_elf()
    ehdr = _parse_ehdr(data)
    phdrs, _phfmt, _phsize = _parse_phdrs(data, ehdr)

    load_segments = [phdr for phdr in phdrs if phdr["p_type"] == PT_LOAD]
    if not load_segments:
        raise RuntimeError("ELF 中没有可扩展的 PT_LOAD 段。")

    target = max(load_segments, key=lambda item: (item["p_offset"] + item["p_filesz"], item["p_vaddr"] + item["p_memsz"]))
    reserve_size = align_up(max(required_size, PATCH_SEGMENT_DEFAULT_SIZE), 0x1000)
    bss_gap = max(0, int(target["p_memsz"]) - int(target["p_filesz"]))
    file_size = len(data)
    raw_ptr = align_up(file_size, PATCH_STUB_ALIGN)
    align_pad = raw_ptr - file_size
    total_growth = align_pad + reserve_size
    ea_start = current_imagebase() + int(target["p_vaddr"]) + (raw_ptr - int(target["p_offset"]))
    new_p_filesz = (raw_ptr + reserve_size) - int(target["p_offset"])
    new_p_memsz = new_p_filesz + bss_gap

    return {
        "exists": False,
        "path": path,
        "binary_kind": "elf",
        "ehdr": ehdr,
        "phdrs": phdrs,
        "target_phdr_index": target["index"],
        "target_flags": target["p_flags"],
        "bss_gap": bss_gap,
        "align_pad": align_pad,
        "growth_size": total_growth,
        "section_name": PATCH_FILE_SECTION_NAME,
        "raw_ptr": raw_ptr,
        "raw_size": reserve_size,
        "ea_start": ea_start,
        "patch_raw_end": raw_ptr + reserve_size,
        "required_size": required_size,
        "new_p_filesz": new_p_filesz,
        "new_p_memsz": new_p_memsz,
    }


def ensure_file_length(path, end_offset):
    """Extend the file with zeros up to `end_offset` bytes."""
    current_size = os.path.getsize(path)
    if current_size >= end_offset:
        return
    with open(path, "r+b") as fh:
        fh.seek(current_size)
        fh.write(b"\x00" * (end_offset - current_size))


def _rewrite_elf_in_place(path, ehdr, phdrs, shdrs, target_index, insert_offset, insert_bytes):
    """Insert bytes into an ELF file in-place and update phdr/shdr offsets."""
    size = len(insert_bytes)

    with open(path, "rb") as fh:
        data = bytearray(fh.read())

    data[insert_offset:insert_offset] = insert_bytes

    if ehdr["e_phoff"] and ehdr["e_phoff"] >= insert_offset:
        ehdr["e_phoff"] += size
    if ehdr["e_shoff"] and ehdr["e_shoff"] >= insert_offset:
        ehdr["e_shoff"] += size

    for phdr in phdrs:
        if phdr["index"] == target_index:
            phdr["p_filesz"] += size
            phdr["p_memsz"] += size
            phdr["p_flags"] |= PF_X
        if phdr["offset_in_file"] >= insert_offset:
            phdr["offset_in_file"] += size
        if phdr["p_offset"] >= insert_offset:
            phdr["p_offset"] += size

    for shdr in shdrs:
        if shdr["offset_in_file"] >= insert_offset:
            shdr["offset_in_file"] += size
        if shdr["sh_type"] != 8 and shdr["sh_offset"] >= insert_offset:
            shdr["sh_offset"] += size

    data[0 : ehdr["ehdr_size"]] = _pack_ehdr(ehdr)
    for phdr in phdrs:
        packed = _pack_phdr(phdr, ehdr["elf_class"], ehdr["endian"])
        start = phdr["offset_in_file"]
        data[start : start + len(packed)] = packed
    for shdr in shdrs:
        packed = _pack_shdr(shdr, ehdr["elf_class"], ehdr["endian"])
        start = shdr["offset_in_file"]
        data[start : start + len(packed)] = packed

    with open(path, "wb") as fh:
        fh.write(data)


def create_elf_patch_segment(required_size):
    """Create a new ELF file-backed patch segment by extending the last PT_LOAD."""
    info = elf_patch_segment_info(required_size)
    if info["exists"]:
        return info

    _data, path = open_input_elf()
    ensure_file_length(path, info["raw_ptr"] + info["raw_size"])

    data, _path = open_input_elf()
    ehdr = _parse_ehdr(data)
    phdrs, _phfmt, _phsize = _parse_phdrs(data, ehdr)
    target = phdrs[info["target_phdr_index"]]
    target["p_filesz"] = info["new_p_filesz"]
    target["p_memsz"] = info["new_p_memsz"]
    target["p_flags"] |= PF_X

    with open(path, "r+b") as fh:
        fh.seek(target["offset_in_file"])
        fh.write(_pack_phdr(target, ehdr["elf_class"], ehdr["endian"]))
    try:
        from .filemap import invalidate_elf_filemap_cache

        invalidate_elf_filemap_cache(path)
    except Exception:
        pass

    debug_log(
        "elf_patch_segment.create",
        path=path,
        raw_ptr="0x%X" % info["raw_ptr"],
        raw_size="0x%X" % info["raw_size"],
        growth_size="0x%X" % info["growth_size"],
        ea_start="0x%X" % info["ea_start"],
    )
    created = dict(info)
    created.update(
        {
            "exists": True,
            "path": path,
            "patch_raw_end": info["raw_ptr"] + info["raw_size"],
        }
    )
    return created


def extend_elf_patch_segment(required_size):
    """Extend the current ELF file-backed patch segment reservation."""
    current = _current_patch_segment_info()
    if current is None:
        return create_elf_patch_segment(required_size)
    if current["raw_size"] >= required_size:
        info = dict(current)
        info.update({"exists": True, "path": input_file_path(), "binary_kind": "elf"})
        return info

    grow_size = align_up(required_size - current["raw_size"], 0x1000)
    data, path = open_input_elf()
    ehdr = _parse_ehdr(data)
    phdrs, _phfmt, _phsize = _parse_phdrs(data, ehdr)

    load_segments = [phdr for phdr in phdrs if phdr["p_type"] == PT_LOAD]
    if not load_segments:
        raise RuntimeError("ELF 中没有可扩展的 PT_LOAD 段。")
    target = max(load_segments, key=lambda item: (item["p_offset"] + item["p_filesz"], item["p_vaddr"] + item["p_memsz"]))
    ensure_file_length(path, current["raw_ptr"] + current["raw_size"] + grow_size)
    bss_gap = max(0, int(target["p_memsz"]) - int(target["p_filesz"]))
    target["p_filesz"] = (current["raw_ptr"] + current["raw_size"] + grow_size) - int(target["p_offset"])
    target["p_memsz"] = int(target["p_filesz"]) + bss_gap
    target["p_flags"] |= PF_X

    with open(path, "r+b") as fh:
        fh.seek(target["offset_in_file"])
        fh.write(_pack_phdr(target, ehdr["elf_class"], ehdr["endian"]))
    try:
        from .filemap import invalidate_elf_filemap_cache

        invalidate_elf_filemap_cache(path)
    except Exception:
        pass

    debug_log(
        "elf_patch_segment.extend",
        path=path,
        grow_size="0x%X" % grow_size,
        old_raw_size="0x%X" % current["raw_size"],
        new_raw_size="0x%X" % (current["raw_size"] + grow_size),
    )
    extended = dict(current)
    extended.update(
        {
            "exists": True,
            "path": path,
            "binary_kind": "elf",
            "raw_size": current["raw_size"] + grow_size,
            "ea_end": int(current["ea_start"]) + int(current["raw_size"] + grow_size),
            "patch_raw_end": int(current["raw_ptr"]) + int(current["raw_size"] + grow_size),
            "required_size": required_size,
        }
    )
    return extended


def sync_elf_patch_segment_to_idb(info):
    """Create or resize the IDA segment that mirrors the ELF patch segment."""
    seg = find_segment_by_name(PATCH_FILE_SECTION_NAME)
    if seg is not None and int(seg.start_ea) != int(info["ea_start"]):
        try:
            ida_segment.del_segm(seg.start_ea, ida_segment.SEGMOD_KILL)
        except Exception:
            pass
        seg = None
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
            raise RuntimeError("无法在 IDA 中创建 ELF 补丁节段 `%s`。" % info["section_name"])
        seg = ida_segment.getseg(info["ea_start"])
    elif seg.end_ea < info["ea_start"] + info["raw_size"]:
        if not ida_segment.set_segm_end(
            seg.start_ea,
            info["ea_start"] + info["raw_size"],
            ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT,
        ):
            raise RuntimeError("无法扩展 IDA 中的 ELF 补丁节段 `%s`。" % info["section_name"])
        seg = ida_segment.getseg(seg.start_ea)

    if seg is None:
        raise RuntimeError("ELF 补丁节段创建后无法重新获取。")

    ida_segment.set_segm_name(seg, info["section_name"])
    ida_segment.set_segm_class(seg, PATCH_SEGMENT_CLASS)
    ida_segment.set_segm_addressing(seg, segment_bitness_code())
    seg.perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_EXEC
    ida_segment.update_segm(seg)
    ida_segment.set_segment_cmt(
        seg,
        f"ida_patch_pro ELF file-backed patch segment. 此段已同步到输入文件，可直接运行/调试。 raw_ptr={info['raw_ptr']:#010x}",
        0,
    )

    ensure_file_length(info["path"], info["raw_ptr"] + info["raw_size"])
    data = read_file_bytes(info["path"], info["raw_ptr"], info["raw_size"])
    if len(data) != info["raw_size"]:
        raise RuntimeError("无法把 ELF 补丁段 `%s` 映射回 IDA 数据库。" % info["section_name"])
    ida_bytes.patch_bytes(info["ea_start"], data)
    debug_log(
        "elf_patch_segment.sync",
        path=info["path"],
        raw_ptr="0x%X" % info["raw_ptr"],
        raw_size="0x%X" % info["raw_size"],
        ea_start="0x%X" % info["ea_start"],
    )
    return seg


def prepare_elf_patch_segment(required_size, apply_changes=False):
    """Ensure an ELF file-backed patch segment exists and is mirrored into IDA."""
    from .filemap import ea_file_offset

    info = elf_patch_segment_info(required_size)
    if apply_changes:
        if info["exists"]:
            info = extend_elf_patch_segment(required_size)
        else:
            info = create_elf_patch_segment(required_size)

    if apply_changes:
        info["segment"] = sync_elf_patch_segment_to_idb(info)
    else:
        info["segment"] = find_segment_by_name(
            PATCH_FILE_SECTION_NAME,
            file_backed=True,
            offset_resolver=ea_file_offset,
        )
    return info
