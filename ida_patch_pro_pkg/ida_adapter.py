"""Thin wrappers around frequently-used IDA APIs."""

import glob
import os
import sys

import ida_bytes
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
