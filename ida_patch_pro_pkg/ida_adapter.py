"""Thin wrappers around frequently-used IDA APIs."""

import glob
import hashlib
import os
import sys

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_loader
import ida_nalt
import ida_segment
import idc

_LAST_RESOLVED_INPUT_PATH = ""


def _normalize_existing_path(path):
    """Normalize one candidate path and keep only existing non-database files."""
    value = (path or "").strip()
    if not value:
        return ""
    try:
        value = os.path.normcase(os.path.abspath(value))
    except Exception:
        return ""
    if not os.path.isfile(value):
        return ""
    if os.path.splitext(value)[1].lower() in (".i64", ".idb", ".id0", ".id1", ".nam", ".til"):
        return ""
    return value


def _database_expected_file_info():
    """Return the current database's recorded input-file size/hash when available."""
    info = {"size": None, "md5": ""}
    getter = getattr(ida_nalt, "retrieve_input_file_size", None)
    if getter is not None:
        try:
            size = int(getter())
            if size > 0:
                info["size"] = size
        except Exception:
            pass

    getter = getattr(ida_nalt, "retrieve_input_file_md5", None)
    if getter is not None:
        try:
            digest = getter()
            if digest:
                info["md5"] = bytes(digest).hex().lower()
        except Exception:
            pass
    return info


def _candidate_matches_database(path, expected):
    """Return whether one on-disk file matches the current database fingerprint."""
    path = _normalize_existing_path(path)
    if not path:
        return False

    expected_size = expected.get("size")
    if expected_size is not None:
        try:
            if os.path.getsize(path) != expected_size:
                return False
        except Exception:
            return False

    expected_md5 = (expected.get("md5") or "").lower()
    if not expected_md5:
        return True

    digest = hashlib.md5()
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except Exception:
        return False
    return digest.hexdigest().lower() == expected_md5


def _root_filename_candidates():
    """Return plausible input-file basenames from the current database."""
    names = []

    getter = getattr(idc, "get_root_filename", None)
    if getter is not None:
        try:
            root = (getter() or "").strip()
            if root:
                names.append(root)
                if "." not in os.path.basename(root):
                    names.append("%s.exe" % root)
        except Exception:
            pass

    for value in (input_file_path_raw(), current_idb_path()):
        base = os.path.basename((value or "").strip())
        if base and base not in names:
            names.append(base)
    return [name for name in names if name]


def _search_matching_input_file(expected):
    """Search nearby directories for a file matching the current database fingerprint."""
    names = _root_filename_candidates()
    if not names:
        return ""

    candidate_dirs = []
    for value in (current_idb_path(), input_file_path_raw()):
        directory = os.path.dirname(_normalize_existing_path(value) or os.path.abspath(value or "")) if value else ""
        if directory and os.path.isdir(directory) and directory not in candidate_dirs:
            candidate_dirs.append(directory)

    extra_dirs = []
    for directory in list(candidate_dirs):
        parent = os.path.dirname(directory)
        if parent and os.path.isdir(parent) and parent not in candidate_dirs and parent not in extra_dirs:
            extra_dirs.append(parent)
    candidate_dirs.extend(extra_dirs)

    matches = []
    for root in candidate_dirs:
        try:
            for dirpath, _dirnames, filenames in os.walk(root):
                for name in names:
                    if name not in filenames:
                        continue
                    candidate = os.path.join(dirpath, name)
                    candidate = _normalize_existing_path(candidate)
                    if not candidate or not _candidate_matches_database(candidate, expected):
                        continue
                    matches.append(candidate)
        except Exception:
            continue

    if not matches:
        return ""

    idb_dir = os.path.dirname(current_idb_path() or "")
    if idb_dir:
        idb_dir = os.path.normcase(os.path.abspath(idb_dir))

        def sort_key(path):
            directory = os.path.normcase(os.path.dirname(path))
            same_dir = 0 if directory == idb_dir else 1
            return (same_dir, len(path), path)

        matches.sort(key=sort_key)
    else:
        matches.sort(key=lambda path: (len(path), path))
    return matches[0]


def input_file_path_raw():
    """Return the raw path reported by IDA without validating it against the database."""
    for getter in (
        lambda: getattr(ida_loader, "get_path", None) and ida_loader.get_path(getattr(ida_loader, "PATH_TYPE_CMD", None)),
        lambda: getattr(idc, "get_input_file_path", None) and idc.get_input_file_path(),
        lambda: getattr(ida_nalt, "get_input_file_path", None) and ida_nalt.get_input_file_path(),
        lambda: getattr(ida_nalt, "dbg_get_input_path", None) and ida_nalt.dbg_get_input_path(),
    ):
        try:
            value = getter()
        except Exception:
            value = ""
        value = _normalize_existing_path(value)
        if value:
            return value
    return ""


def input_file_path():
    """Return the input file path of the current IDA database."""
    global _LAST_RESOLVED_INPUT_PATH
    expected = _database_expected_file_info()
    raw_candidates = []

    for getter in (
        lambda: getattr(ida_loader, "get_path", None) and ida_loader.get_path(getattr(ida_loader, "PATH_TYPE_CMD", None)),
        lambda: getattr(idc, "get_input_file_path", None) and idc.get_input_file_path(),
        lambda: getattr(ida_nalt, "get_input_file_path", None) and ida_nalt.get_input_file_path(),
        lambda: getattr(ida_nalt, "dbg_get_input_path", None) and ida_nalt.dbg_get_input_path(),
    ):
        try:
            value = getter()
        except Exception:
            value = ""
        path = _normalize_existing_path(value)
        if path and path not in raw_candidates:
            raw_candidates.append(path)
        if path and _candidate_matches_database(path, expected):
            _LAST_RESOLVED_INPUT_PATH = path
            return path

    matched = _search_matching_input_file(expected)
    if matched:
        _LAST_RESOLVED_INPUT_PATH = matched
        return matched

    cached = _normalize_existing_path(_LAST_RESOLVED_INPUT_PATH)
    if cached:
        return cached

    if raw_candidates:
        _LAST_RESOLVED_INPUT_PATH = raw_candidates[0]
        return raw_candidates[0]

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
