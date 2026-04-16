"""IDB and file-backed trampoline cave discovery/allocation helpers."""

import ida_bytes
import ida_segment
import idc

from ..backends.filemap import ea_file_offset
from ..constants import (
    FILE_CAVE_FILL_BYTES,
    PATCH_SEGMENT_CLASS,
    PATCH_SEGMENT_DEFAULT_SIZE,
    PATCH_SEGMENT_NAME,
    PATCH_STUB_ALIGN,
)
from ..ida_adapter import segment_name
from ..logging_utils import debug_log


def align_up(value, alignment):
    """Round a value up to the next multiple of `alignment`."""
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def is_file_backed_executable_segment(seg):
    """Return whether the segment is executable and mapped to the input file."""
    if seg is None:
        return False
    if not (getattr(seg, "perm", 0) & ida_segment.SEGPERM_EXEC):
        return False
    return ea_file_offset(seg.start_ea) is not None


def is_file_cave_byte(ea):
    """Return whether the byte is an unknown filler byte suitable for a file cave."""
    if ea_file_offset(ea) is None:
        return False
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.get_byte(ea) not in FILE_CAVE_FILL_BYTES:
        return False
    if ida_bytes.is_unknown(flags):
        return True
    is_align = getattr(ida_bytes, "is_align", None)
    if callable(is_align):
        try:
            if is_align(flags):
                return True
        except Exception:
            pass
    return False


def file_cave_candidates(preferred_ea=None):
    """Yield executable file-backed segments, preferring the one near `preferred_ea`."""
    segments = []
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if is_file_backed_executable_segment(seg):
            segments.append(seg)

    def sort_key(seg):
        if preferred_ea is None:
            return (seg.start_ea, seg.end_ea)
        in_same_seg = 0 if seg.start_ea <= preferred_ea < seg.end_ea else 1
        distance = 0
        if preferred_ea < seg.start_ea:
            distance = seg.start_ea - preferred_ea
        elif preferred_ea >= seg.end_ea:
            distance = preferred_ea - seg.end_ea
        return (in_same_seg, distance, seg.start_ea)

    return sorted(segments, key=sort_key)


def find_file_code_cave(required_size, preferred_ea=None, alignment=PATCH_STUB_ALIGN):
    """Find a file-backed executable code cave made of unknown filler bytes."""
    if required_size <= 0:
        raise RuntimeError("无效的代码洞大小: %d" % required_size)

    for seg in file_cave_candidates(preferred_ea):
        current = seg.start_ea
        while current < seg.end_ea:
            while current < seg.end_ea and not is_file_cave_byte(current):
                current += 1
            run_start = current
            while current < seg.end_ea and is_file_cave_byte(current):
                current += 1
            run_end = current
            if run_end <= run_start:
                continue
            cave_start = align_up(run_start, alignment)
            if cave_start + required_size <= run_end:
                debug_log(
                    "file_cave.find",
                    segment=segment_name(seg),
                    cave_start="0x%X" % cave_start,
                    required_size=required_size,
                    run_start="0x%X" % run_start,
                    run_end="0x%X" % run_end,
                )
                return {
                    "segment": seg,
                    "start": cave_start,
                    "run_start": run_start,
                    "run_end": run_end,
                    "available_size": run_end - cave_start,
                }

    raise RuntimeError(
        "未找到可写回输入文件的代码洞。请先在可执行段中准备一段未使用的 00/90/CC 填充区。"
    )


def max_segment_end():
    """Return the highest end address among all segments."""
    max_end = 0
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is not None and seg.end_ea > max_end:
            max_end = seg.end_ea
    return max_end


def patch_segment_bitness():
    """Return IDA segment bitness code for the current database."""
    if idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT:
        return 2
    return 1


def find_patch_segment():
    """Find the dedicated trampoline/code-cave segment if it already exists."""
    return ida_segment.get_segm_by_name(PATCH_SEGMENT_NAME)


def next_patch_cursor(seg):
    """Return the next aligned free address inside the patch segment."""
    cursor = seg.start_ea
    current = seg.start_ea
    while current < seg.end_ea:
        flags = ida_bytes.get_flags(current)
        if ida_bytes.is_unknown(flags):
            break
        item_size = ida_bytes.get_item_size(current)
        if item_size <= 0:
            item_size = 1
        item_end = current + item_size
        if item_end > cursor:
            cursor = item_end
        current = item_end
    return align_up(cursor, PATCH_STUB_ALIGN)


def preview_patch_segment_allocation(required_size=0):
    """Describe where the next IDB-only cave would start without mutating the database."""
    seg = find_patch_segment()
    if seg is None:
        start_ea = align_up(max_segment_end() + 0x1000, 0x1000)
        return {
            "segment": None,
            "segment_name": PATCH_SEGMENT_NAME,
            "cave_start": start_ea,
            "alloc_base_ea": start_ea,
            "would_create": True,
            "required_size": required_size,
        }
    return {
        "segment": seg,
        "segment_name": PATCH_SEGMENT_NAME,
        "cave_start": next_patch_cursor(seg),
        "alloc_base_ea": int(seg.start_ea),
        "would_create": False,
        "required_size": required_size,
    }


def ensure_patch_segment(required_size):
    """Create or extend the dedicated patch segment to fit a new trampoline stub."""
    seg = find_patch_segment()
    if seg is None:
        start_ea = align_up(max_segment_end() + 0x1000, 0x1000)
        seg_size = align_up(max(PATCH_SEGMENT_DEFAULT_SIZE, required_size + 0x100), 0x1000)
        if not ida_segment.add_segm(
            start_ea >> 4,
            start_ea,
            start_ea + seg_size,
            PATCH_SEGMENT_NAME,
            PATCH_SEGMENT_CLASS,
            ida_segment.ADDSEG_QUIET | ida_segment.ADDSEG_NOSREG | ida_segment.ADDSEG_NOTRUNC,
        ):
            raise RuntimeError("无法创建代码洞段 `%s`。" % PATCH_SEGMENT_NAME)
        seg = ida_segment.getseg(start_ea)
        if seg is None:
            raise RuntimeError("代码洞段创建后无法重新获取。")
        ida_segment.set_segm_class(seg, PATCH_SEGMENT_CLASS)
        ida_segment.set_segm_addressing(seg, patch_segment_bitness())
        seg.perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_EXEC
        ida_segment.update_segm(seg)
        ida_segment.set_segment_cmt(
            seg,
            "ida_patch_pro trampoline segment. 默认只存在于 IDB，中转逻辑不自动扩展原始文件布局。",
            0,
        )
        debug_log(
            "patch_segment.create",
            name=PATCH_SEGMENT_NAME,
            start="0x%X" % start_ea,
            size="0x%X" % seg_size,
        )
        return ida_segment.getseg(start_ea)

    cursor = next_patch_cursor(seg)
    if seg.end_ea - cursor < required_size:
        new_end = align_up(cursor + required_size + 0x100, 0x1000)
        if not ida_segment.set_segm_end(
            seg.start_ea,
            new_end,
            ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT,
        ):
            raise RuntimeError("无法扩展代码洞段 `%s` 到 0x%X。" % (PATCH_SEGMENT_NAME, new_end))
        seg = ida_segment.getseg(seg.start_ea)
        debug_log(
            "patch_segment.extend",
            name=PATCH_SEGMENT_NAME,
            start="0x%X" % seg.start_ea,
            new_end="0x%X" % new_end,
            required_size="0x%X" % required_size,
        )
    return seg
