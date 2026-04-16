"""Thin wrappers around frequently-used IDA APIs."""

import glob
import os
import sys

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_loader
import ida_nalt
import ida_segment
import idc


def input_file_path():
    """Return the input file path of the current IDA database."""
    getter = getattr(idc, "get_input_file_path", None)
    if getter is None:
        return ""
    try:
        return getter() or ""
    except Exception:
        return ""


def current_idb_path():
    """Return the current IDB path when IDA exposes it."""
    getter = getattr(idc, "get_idb_path", None)
    if getter is None:
        return ""
    try:
        return getter() or ""
    except Exception:
        return ""


def current_database_identity():
    """Return a stable-ish identity string for the currently opened database."""
    idb_path = current_idb_path()
    if idb_path:
        return "idb:%s" % os.path.normcase(os.path.abspath(idb_path))
    input_path = input_file_path()
    if input_path:
        return "input:%s" % os.path.normcase(os.path.abspath(input_path))
    return "imagebase:0x%X" % current_imagebase()


def current_database_label():
    """Return a short user-facing label for the current database."""
    idb_path = current_idb_path()
    if idb_path:
        return os.path.basename(idb_path)
    input_path = input_file_path()
    if input_path:
        return os.path.basename(input_path)
    return "imagebase_0x%X" % current_imagebase()


def load_pefile_module():
    """Import `pefile` from IDA Python or common Windows Python installs."""
    try:
        import pefile  # type: ignore

        return pefile
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

    for env_name in ("APPDATA", "LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name)
        if not base:
            continue
        for root in glob.glob(os.path.join(base, "Python*")):
            add_dir(os.path.join(root, "Lib", "site-packages"))
        for root in glob.glob(os.path.join(base, "Python", "Python*")):
            add_dir(os.path.join(root, "site-packages"))
            add_dir(os.path.join(root, "Lib", "site-packages"))
        for root in glob.glob(os.path.join(base, "Programs", "Python", "Python*")):
            add_dir(os.path.join(root, "Lib", "site-packages"))

    for path in candidates:
        if path not in sys.path:
            sys.path.append(path)
        try:
            import pefile  # type: ignore

            return pefile
        except Exception:
            continue

    return None


def segment_name(seg):
    """Return a segment name safely."""
    if seg is None:
        return ""
    try:
        return ida_segment.get_segm_name(seg) or ""
    except Exception:
        return ""


def iter_segments():
    """Yield all IDA segments."""
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is not None:
            yield seg


def find_segment_by_name(name, file_backed=None, offset_resolver=None):
    """Find a segment by exact name, optionally filtering by file-backed mapping."""
    for seg in iter_segments():
        if segment_name(seg) != name:
            continue
        if file_backed is None:
            return seg
        mapped = False
        if offset_resolver is not None:
            mapped = offset_resolver(seg.start_ea) is not None
        if mapped == file_backed:
            return seg
    return None


def read_file_bytes(path, offset, size):
    """Read a fixed-size byte range from a file."""
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(size)
    return data


def read_idb_bytes(ea, size):
    """Read a fixed-size byte range from the current database."""
    if size <= 0:
        return b""
    buf = ida_bytes.get_bytes(ea, size)
    if not buf:
        return b"\x00" * size
    data = bytes(buf)
    if len(data) < size:
        data += b"\x00" * (size - len(data))
    return data


def current_imagebase():
    """Return the current database image base."""
    getter = getattr(ida_nalt, "get_imagebase", None)
    if getter is not None:
        try:
            return int(getter())
        except Exception:
            pass
    getter = getattr(idc, "get_imagebase", None)
    if getter is not None:
        try:
            return int(getter())
        except Exception:
            pass
    return 0


def database_min_ea():
    """Return the database min EA with broad IDA-version compatibility."""
    getter = getattr(idc, "get_inf_attr", None)
    if getter is not None:
        try:
            value = int(getter(idc.INF_MIN_EA))
            if value:
                return value
        except Exception:
            pass
    return current_imagebase()


def database_max_ea():
    """Return the database max EA with broad IDA-version compatibility."""
    getter = getattr(idc, "get_inf_attr", None)
    if getter is not None:
        try:
            value = int(getter(idc.INF_MAX_EA))
            if value:
                return value
        except Exception:
            pass

    max_ea = database_min_ea()
    for seg in iter_segments():
        max_ea = max(max_ea, int(seg.end_ea))
    return max_ea


def is_64bit_database():
    """Return whether the current database is 64-bit."""
    try:
        return bool(idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT)
    except Exception:
        return False


def segment_bitness_code():
    """Return IDA's segment bitness code for the current database."""
    return 2 if is_64bit_database() else 1


def preferred_imagebase():
    """Return IDA's preferred image base if available."""
    getter = getattr(idc, "get_inf_attr", None)
    if getter is not None:
        try:
            return int(getter(idc.INF_MIN_EA))
        except Exception:
            pass
    return current_imagebase()


def transaction_imagebase(meta=None):
    """Return the best image base to store in history metadata."""
    meta = meta or {}
    imagebase = current_imagebase()
    if imagebase:
        return imagebase
    return int(meta.get("imagebase") or preferred_imagebase() or 0)


def rebase_history_ea(ea, stored_imagebase):
    """Rebase a stored EA to the current image base when the database moved."""
    if ea is None:
        return None
    stored_imagebase = int(stored_imagebase or 0)
    imagebase = current_imagebase()
    if not stored_imagebase or not imagebase or stored_imagebase == imagebase:
        return ea
    return int(ea) - stored_imagebase + imagebase


def segment_is_executable(seg):
    """Return whether the given segment is executable."""
    if seg is None:
        return False
    perm = getattr(seg, "perm", 0)
    return bool(perm & getattr(ida_segment, "SEGPERM_EXEC", 0))


def segment_range_for_ea(ea):
    """Return the segment bounds and name that contain the given EA."""
    seg = ida_segment.getseg(ea)
    if seg is None:
        return None
    return {
        "start_ea": int(seg.start_ea),
        "end_ea": int(seg.end_ea),
        "name": segment_name(seg),
        "is_executable": segment_is_executable(seg),
    }


def function_range_for_ea(ea):
    """Return the function bounds and name that contain the given EA."""
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    try:
        name = idc.get_func_name(func.start_ea) or ""
    except Exception:
        name = ""
    return {
        "start_ea": int(func.start_ea),
        "end_ea": int(func.end_ea),
        "name": name,
    }


def resolve_ea_text(text):
    """Resolve a user-supplied EA string from a symbol name or numeric literal."""
    value = (text or "").strip()
    if not value:
        return None

    try:
        ea = idc.get_name_ea_simple(value)
    except Exception:
        ea = ida_idaapi.BADADDR
    if ea != ida_idaapi.BADADDR:
        return int(ea)

    try:
        from .asm.operands import parse_immediate_value

        parsed = parse_immediate_value(value)
    except Exception:
        parsed = None
    if parsed is not None:
        return int(parsed)
    return None


def add_segm_ex_compat(start_ea, end_ea, base, bitness, sa, sclass, flags):
    """兼容 IDA 9.2+ 的 add_segm_ex 封装。

    IDA 9.2 将 add_segm_ex 签名从 7 个位置参数改为 4 个：
        add_segm_ex(segment_t, name, sclass, flags)
    旧版签名：
        add_segm_ex(start_ea, end_ea, base, bitness, sa, sclass, flags)

    此函数尝试三种方案：
    1. 新 API add_segm_ex(segment_t, name, sclass, flags)
    2. 替代 API add_segm(para, start, end, name, sclass, flags)
    3. 回退旧 API add_segm_ex(7参数)
    """
    # 确保 sclass 是字符串
    if isinstance(sclass, int):
        # 尝试映射常见的 sc* 常量到字符串
        sc_map = {
            getattr(ida_segment, 'scPub', 0): 'CODE',
            getattr(ida_segment, 'scCode', 0): 'CODE',
            getattr(ida_segment, 'scData', 0): 'DATA',
            getattr(ida_segment, 'scBss', 0): 'BSS',
        }
        sclass = sc_map.get(sclass, 'CODE')

    # 方案1：新 API add_segm_ex(segment_t, name, sclass, flags)
    try:
        seg = ida_segment.segment_t()
        seg.start_ea = start_ea
        seg.end_ea = end_ea
        seg.bitness = bitness
        seg.align = sa
        seg.comb = ida_segment.scPub
        name = None
        return ida_segment.add_segm_ex(seg, name, sclass, flags)
    except (TypeError, AttributeError):
        pass

    # 方案2：替代 API add_segm(para, start, end, name, sclass, flags)
    try:
        para = start_ea >> 4
        name = None
        result = ida_segment.add_segm(para, start_ea, end_ea, name, sclass, flags)
        if result:
            # add_segm 不会自动设置 bitness，需要手动设置
            seg = ida_segment.getseg(start_ea)
            if seg is not None:
                seg.bitness = bitness
                ida_segment.update_segm(seg)
        return result
    except (TypeError, AttributeError):
        pass

    # 方案3：回退旧 API add_segm_ex(7参数)
    try:
        return ida_segment.add_segm_ex(start_ea, end_ea, base, bitness, sa, sclass, flags)
    except (TypeError, AttributeError):
        raise RuntimeError("add_segm_ex: 无法适配当前 IDA 版本的 API 签名。")
