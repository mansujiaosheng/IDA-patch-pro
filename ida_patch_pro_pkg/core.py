"""IDA 右键汇编修改插件。

功能概览：
1. 在反汇编右键菜单中提供“修改汇编”和“NOP”操作。
2. 打开自定义 Assemble 窗口，支持机器码预览、语法帮助、模板建议。
3. 对 IDA 显示用的栈变量表达式做自动折算，并为 x86/x64 提供 Keystone 兜底汇编。
"""

import ida_auto
import ida_bytes
import ida_diskio
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_nalt
import ida_segment
import ida_ua
import idc
import idautils
import glob
import json
import os
import re
import shutil
import subprocess
import struct
import sys
import time
import traceback


# 插件显示名称，以及两个右键动作的唯一 ID。
PLUGIN_NAME = "ida_patch_pro"
ACTION_ASSEMBLE = "ida_patch_pro:assemble"
ACTION_NOP = "ida_patch_pro:nop"
ACTION_TRAMPOLINE = "ida_patch_pro:trampoline"
ACTION_ROLLBACK = "ida_patch_pro:rollback"
ACTION_SHORTCUTS = "ida_patch_pro:shortcut_settings"
MAIN_MENU_NAME = "ida_patch_pro_menu"
MAIN_MENU_LABEL = PLUGIN_NAME
MAIN_MENU_PARENT_PATH = "Edit/Patch program/"
MAIN_MENU_PATH = "%s%s/" % (MAIN_MENU_PARENT_PATH, MAIN_MENU_LABEL)

PATCH_SEGMENT_NAME = ".patch"
PATCH_FILE_SECTION_NAME = ".patchf"
PATCH_SEGMENT_CLASS = "CODE"
PATCH_SEGMENT_DEFAULT_SIZE = 0x2000
PATCH_STUB_ALIGN = 0x10
TEST_LOG_FILENAME = "ida_patch_pro.test.log"
HISTORY_FILENAME = "ida_patch_pro.history.json"
SETTINGS_FILENAME = "ida_patch_pro.settings.json"
FILE_CAVE_FILL_BYTES = {0x00, 0x90, 0xCC}
TRAMPOLINE_ORIG_MARKER_RE = re.compile(r"(?is)^\{\{\s*orig(?:\s*:\s*(all|\d+))?\s*\}\}$")
PE_SECTION_CHARACTERISTICS_RX = 0x60000020
_MODELLESS_DIALOGS = []

ACTION_SHORTCUT_SPECS = [
    (ACTION_ASSEMBLE, "修改汇编", "Ctrl+Alt+A"),
    (ACTION_TRAMPOLINE, "代码注入", "Ctrl+Alt+T"),
    (ACTION_NOP, "NOP", "Ctrl+Alt+N"),
    (ACTION_ROLLBACK, "补丁回撤列表", "Ctrl+Alt+R"),
    (ACTION_SHORTCUTS, "快捷键设置", ""),
]

from .data import (
    ARCH_REGISTER_HELP,
    ARCH_SYNTAX_HELP,
    MNEMONIC_HINTS,
    REGISTER_HINTS,
    _register_hint,
)

def _current_ea(ctx):
    """Return the current EA from popup context, falling back to screen EA."""
    ea = getattr(ctx, "cur_ea", ida_idaapi.BADADDR)
    if ea == ida_idaapi.BADADDR:
        ea = ida_kernwin.get_screen_ea()
    return ea


def _selected_items(ctx):
    """Return selected disassembly items or the single current instruction."""
    widget = getattr(ctx, "widget", None)
    has_selection, start_ea, end_ea = ida_kernwin.read_range_selection(widget)
    if has_selection and start_ea != ida_idaapi.BADADDR and end_ea > start_ea:
        heads = list(idautils.Heads(start_ea, end_ea))
        if heads:
            return [(ea, ida_bytes.get_item_size(ea)) for ea in heads]
        return [(start_ea, end_ea - start_ea)]

    ea = _current_ea(ctx)
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        size = 1
    return [(ea, size)]


def _patch_region(ctx):
    """Return patch start, length, user-facing description, and selection state."""
    widget = getattr(ctx, "widget", None)
    has_selection, start_ea, end_ea = ida_kernwin.read_range_selection(widget)
    if has_selection and start_ea != ida_idaapi.BADADDR and end_ea > start_ea:
        return start_ea, end_ea - start_ea, "选中范围 0x%X - 0x%X" % (start_ea, end_ea), True

    ea = _current_ea(ctx)
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        size = 1
    return ea, size, "当前地址 0x%X" % ea, False


def _format_bytes_hex(buf):
    """Format raw bytes as upper-case hex pairs for UI display."""
    if not buf:
        return "(none)"
    return " ".join("%02X" % b for b in buf)


def _test_log_path():
    """Return the local test log path next to the plugin file."""
    try:
        base = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        base = os.getcwd()
    return os.path.join(base, TEST_LOG_FILENAME)


def _runtime_file_path(filename):
    """Return the preferred runtime file path next to the plugin file."""
    try:
        base = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        base = os.getcwd()
    return os.path.join(base, filename)


def _log_preview_text(value, limit=600):
    """Format a value into a single-line log fragment."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = _format_bytes_hex(value)
    else:
        text = str(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > limit:
        text = "%s...(truncated %d chars)" % (text[:limit], len(text) - limit)
    return text


def _debug_log(event, **fields):
    """Append one diagnostic record for the current testing session."""
    try:
        line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), event)
        parts = []
        for key in sorted(fields):
            value = fields[key]
            if value is None or value == "":
                continue
            parts.append("%s=%s" % (key, _log_preview_text(value)))
        if parts:
            line = "%s | %s" % (line, " | ".join(parts))
        with open(_test_log_path(), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def _debug_log_exception(event, exc, **fields):
    """Record an exception and traceback without affecting plugin behavior."""
    fields = dict(fields)
    fields["error"] = "%s: %s" % (exc.__class__.__name__, exc)
    _debug_log(event, **fields)
    try:
        tb = traceback.format_exc()
    except Exception:
        tb = ""
    if tb and tb.strip() != "NoneType: None":
        _debug_log("%s.traceback" % event, traceback=tb)


def _make_trace_id(prefix, ea):
    """Create a short identifier so one test action can be correlated in logs."""
    return "%s-%X-%d" % (prefix, ea, int(time.time() * 1000))


def _input_file_path():
    """Return the input file path of the current IDA database."""
    getter = getattr(idc, "get_input_file_path", None)
    if getter is None:
        return ""
    try:
        return getter() or ""
    except Exception:
        return ""


def _load_pefile_module():
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


def _segment_name(seg):
    """Return a segment name safely."""
    if seg is None:
        return ""
    try:
        return ida_segment.get_segm_name(seg) or ""
    except Exception:
        return ""


def _iter_segments():
    """Yield all IDA segments."""
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is not None:
            yield seg


def _find_segment_by_name(name, file_backed=None):
    """Find a segment by exact name, optionally filtering by file-backed mapping."""
    for seg in _iter_segments():
        if _segment_name(seg) != name:
            continue
        if file_backed is None:
            return seg
        mapped = _ea_file_offset(seg.start_ea) is not None
        if mapped == file_backed:
            return seg
    return None


def _ea_file_offset(ea):
    """Map an EA to its file offset, or return None for non-file-backed bytes."""
    try:
        offset = ida_loader.get_fileregion_offset(ea)
    except Exception:
        offset = None
    if offset is not None and offset != ida_idaapi.BADADDR and (not isinstance(offset, int) or offset >= 0):
        return offset

    seg = ida_segment.getseg(ea)
    if seg is not None and _segment_name(seg) == PATCH_FILE_SECTION_NAME:
        try:
            info = _pe_patch_section_info(0)
        except Exception:
            info = None
        if info and info.get("exists"):
            start = info["ea_start"]
            end = start + info["raw_size"]
            if start <= ea < end:
                file_offset = info["raw_ptr"] + (ea - start)
                _debug_log(
                    "fileregion.fallback",
                    ea="0x%X" % ea,
                    file_offset="0x%X" % file_offset,
                    section=PATCH_FILE_SECTION_NAME,
                )
                return file_offset
    return None


def _build_file_patch_chunks(ea, patch_bytes):
    """Convert an EA-based patch into file write chunks."""
    if not patch_bytes:
        return []

    chunks = []
    chunk_offset = None
    chunk = bytearray()
    for index, value in enumerate(patch_bytes):
        file_offset = _ea_file_offset(ea + index)
        if file_offset is None:
            raise RuntimeError("地址 0x%X 不映射到输入文件，无法写回文件。" % (ea + index))
        if chunk_offset is None:
            chunk_offset = file_offset
        elif file_offset != chunk_offset + len(chunk):
            chunks.append((chunk_offset, bytes(chunk)))
            chunk_offset = file_offset
            chunk = bytearray()
        chunk.append(value)

    if chunk:
        chunks.append((chunk_offset, bytes(chunk)))
    return chunks


def _write_patch_chunks_to_input_file(chunks):
    """Write prepared file chunks back to the original input file."""
    if not chunks:
        return ""

    path = _input_file_path()
    if not path:
        raise RuntimeError("当前 IDB 没有关联输入文件，无法写回文件。")
    if not os.path.isfile(path):
        raise RuntimeError("输入文件不存在: %s" % path)

    with open(path, "r+b") as fh:
        for offset, data in chunks:
            fh.seek(offset)
            fh.write(data)
    return path


def _history_file_path():
    """Return the JSON file used to persist plugin patch history."""
    return _runtime_file_path(HISTORY_FILENAME)


def _settings_file_path():
    """Return the JSON file used to persist plugin settings."""
    return _runtime_file_path(SETTINGS_FILENAME)


def _load_plugin_settings():
    """Load plugin settings from disk."""
    path = _settings_file_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        _debug_log_exception("settings.load.failure", exc, path=path)
        return {}
    return data if isinstance(data, dict) else {}


def _save_plugin_settings(data):
    """Persist plugin settings to disk."""
    with open(_settings_file_path(), "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def _normalize_shortcut_text(value):
    """Normalize one shortcut string for storage and registration."""
    return " ".join((value or "").strip().split())


def _default_action_shortcuts():
    """Return the built-in action shortcut map."""
    return {action_name: default_shortcut for action_name, _label, default_shortcut in ACTION_SHORTCUT_SPECS}


def _load_action_shortcuts():
    """Load configured shortcuts, falling back to built-in defaults."""
    shortcuts = _default_action_shortcuts()
    raw = _load_plugin_settings().get("shortcuts")
    if isinstance(raw, dict):
        for action_name in shortcuts:
            if action_name not in raw:
                continue
            shortcuts[action_name] = _normalize_shortcut_text(raw.get(action_name))
    return shortcuts


def _save_action_shortcuts(shortcuts):
    """Persist action shortcuts to the plugin settings file."""
    settings = _load_plugin_settings()
    settings["shortcuts"] = {
        action_name: _normalize_shortcut_text(shortcuts.get(action_name))
        for action_name, _label, _default_shortcut in ACTION_SHORTCUT_SPECS
    }
    _save_plugin_settings(settings)


def _shortcut_or_none(value):
    """Convert an empty shortcut string to None for IDA registration APIs."""
    value = _normalize_shortcut_text(value)
    return value or None


def _apply_registered_shortcuts(shortcuts):
    """Apply shortcuts to already registered actions when IDA supports it."""
    updater = getattr(ida_kernwin, "update_action_shortcut", None)
    if updater is None:
        return False
    try:
        for action_name, _label, _default_shortcut in ACTION_SHORTCUT_SPECS:
            updater(action_name, _shortcut_or_none(shortcuts.get(action_name)))
        return True
    except Exception as exc:
        _debug_log_exception("settings.apply_shortcuts.failure", exc)
        return False


def _iter_plugin_action_names():
    """Yield every registered plugin action name in display order."""
    for action_name, _label, _default_shortcut in ACTION_SHORTCUT_SPECS:
        yield action_name


def _attach_main_menu_actions():
    """Expose plugin actions in a dedicated submenu under Edit/Patch program."""
    creator = getattr(ida_kernwin, "create_menu", None)
    attacher = getattr(ida_kernwin, "attach_action_to_menu", None)
    if creator is None or attacher is None:
        return False
    try:
        creator(MAIN_MENU_NAME, MAIN_MENU_LABEL, MAIN_MENU_PARENT_PATH)
        attached_any = False
        for action_name in _iter_plugin_action_names():
            if attacher(MAIN_MENU_PATH, action_name, ida_kernwin.SETMENU_APP):
                attached_any = True
        return attached_any
    except Exception as exc:
        _debug_log_exception("menu.attach.failure", exc, menu_path=MAIN_MENU_PATH)
        return False


def _detach_main_menu_actions():
    """Remove previously attached top-menu actions and the custom submenu."""
    detacher = getattr(ida_kernwin, "detach_action_from_menu", None)
    deleter = getattr(ida_kernwin, "delete_menu", None)
    try:
        if detacher is not None:
            for action_name in _iter_plugin_action_names():
                detacher(MAIN_MENU_PATH, action_name)
        if deleter is not None:
            deleter(MAIN_MENU_NAME)
    except Exception as exc:
        _debug_log_exception("menu.detach.failure", exc, menu_path=MAIN_MENU_PATH)


def _load_patch_history():
    """Load persisted patch transactions from disk."""
    path = _history_file_path()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        _debug_log_exception("history.load.failure", exc, path=path)
        return []
    return data if isinstance(data, list) else []


def _save_patch_history(entries):
    """Persist patch transactions to disk."""
    path = _history_file_path()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, ensure_ascii=False, indent=2)


def _read_file_bytes(path, offset, size):
    """Read a fixed-size byte range from a file."""
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(size)
    return data


def _read_idb_bytes(ea, size):
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


def _current_imagebase():
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


def _preferred_imagebase():
    """Return the preferred PE image base when available."""
    try:
        pe, _ = _open_input_pe()
        return int(pe.OPTIONAL_HEADER.ImageBase)
    except Exception:
        return _current_imagebase()


def _transaction_imagebase(meta=None):
    """Return the stored image base for one transaction or operation."""
    if meta and meta.get("imagebase") is not None:
        return int(meta["imagebase"])
    return _preferred_imagebase()


def _rebase_history_ea(ea, stored_imagebase):
    """Translate one stored EA to the current rebased database address."""
    if ea is None:
        return None
    current_imagebase = _current_imagebase()
    if not stored_imagebase:
        return ea
    return ea + (current_imagebase - stored_imagebase)


def _resolve_operation_ea(operation, entry_meta=None):
    """Resolve a recorded operation EA into the current database address."""
    stored_imagebase = operation.get("imagebase")
    if stored_imagebase is None:
        stored_imagebase = _transaction_imagebase(entry_meta)
    return _rebase_history_ea(operation.get("ea"), int(stored_imagebase or 0))


def _capture_patch_operation(ea, patch_bytes, write_to_file=False, note=""):
    """Capture pre-patch bytes so the operation can later be rolled back."""
    seg = ida_segment.getseg(ea)
    operation = {
        "ea": ea,
        "imagebase": _current_imagebase(),
        "segment_name": _segment_name(seg),
        "segment_offset": (ea - seg.start_ea) if seg is not None else 0,
        "size": len(patch_bytes),
        "old_bytes_hex": _read_idb_bytes(ea, len(patch_bytes)).hex(),
        "new_bytes_hex": bytes(patch_bytes).hex(),
        "write_to_file": bool(write_to_file),
        "file_path": "",
        "file_chunks": [],
        "note": note or "",
    }
    if write_to_file:
        path = _input_file_path()
        chunks = _build_file_patch_chunks(ea, patch_bytes)
        file_chunks = []
        for offset, data in chunks:
            file_chunks.append(
                {
                    "offset": offset,
                    "old_bytes_hex": _read_file_bytes(path, offset, len(data)).hex(),
                    "new_bytes_hex": data.hex(),
                }
            )
        operation["file_path"] = path
        operation["file_chunks"] = file_chunks
    return operation


def _apply_operation_bytes(operation, revert=False):
    """Apply one recorded operation either forward or backward."""
    current_ea = _resolve_operation_ea(operation)
    patch_bytes = bytes.fromhex(
        operation["old_bytes_hex"] if revert else operation["new_bytes_hex"]
    )
    if operation.get("write_to_file") and operation.get("file_chunks"):
        path = operation.get("file_path") or _input_file_path()
        if not path or not os.path.isfile(path):
            raise RuntimeError("回撤失败：输入文件不存在。")
        with open(path, "r+b") as fh:
            for chunk in operation["file_chunks"]:
                chunk_bytes = bytes.fromhex(
                    chunk["old_bytes_hex"] if revert else chunk["new_bytes_hex"]
                )
                fh.seek(chunk["offset"])
                fh.write(chunk_bytes)
    _patch_bytes_as_code(current_ea, patch_bytes)


def _begin_patch_transaction(kind, label, target_ea, trace_id="", meta=None):
    """Create a history transaction that groups one logical patch action."""
    meta = dict(meta or {})
    meta.setdefault("imagebase", _current_imagebase())
    return {
        "tx_id": trace_id or _make_trace_id(kind, target_ea),
        "kind": kind,
        "label": label,
        "target_ea": target_ea,
        "created_at": time.time(),
        "status": "active",
        "ops": [],
        "meta": meta,
    }


def _record_transaction_operation(transaction, ea, patch_bytes, write_to_file=False, note=""):
    """Append one operation snapshot into a transaction before applying it."""
    transaction["ops"].append(
        _capture_patch_operation(
            ea,
            patch_bytes,
            write_to_file=write_to_file,
            note=note,
        )
    )


def _commit_patch_transaction(transaction):
    """Persist a completed patch transaction so it can be rolled back later."""
    if not transaction.get("ops"):
        return
    entries = _load_patch_history()
    entries.append(transaction)
    _save_patch_history(entries)
    _debug_log(
        "history.commit",
        tx_id=transaction["tx_id"],
        kind=transaction["kind"],
        target_ea="0x%X" % transaction["target_ea"],
        op_count=len(transaction["ops"]),
    )


def _history_entry_matches_ea(entry, ea):
    """Return whether the address overlaps any active operation of the entry."""
    meta = entry.get("meta") or {}
    for operation in entry.get("ops") or []:
        start = _resolve_operation_ea(operation, meta)
        size = operation.get("size", 0)
        if start <= ea < start + max(size, 1):
            return True
    stored_imagebase = _transaction_imagebase(meta)
    cave_start = _rebase_history_ea(meta.get("cave_start"), stored_imagebase)
    cave_end = _rebase_history_ea(meta.get("cave_end"), stored_imagebase)
    if cave_start is not None and cave_end is not None and cave_start <= ea < cave_end:
        return True
    return False


def _find_active_history_entry(ea=None):
    """Find the latest active transaction, preferring one that covers `ea`."""
    entries = _load_patch_history()
    for entry in reversed(entries):
        if entry.get("status") != "active":
            continue
        if ea is None or _history_entry_matches_ea(entry, ea):
            return entry
    return None


def _mark_transaction_rolled_back(tx_id):
    """Mark a transaction as rolled back without deleting its history record."""
    entries = _load_patch_history()
    changed = False
    for entry in entries:
        if entry.get("tx_id") != tx_id:
            continue
        entry["status"] = "rolled_back"
        entry["rolled_back_at"] = time.time()
        changed = True
        break
    if changed:
        _save_patch_history(entries)


def _cleanup_trampoline_tail(meta):
    """Best-effort cleanup for a trampoline cave that had been attached as a tail chunk."""
    stored_imagebase = _transaction_imagebase(meta)
    cave_start = _rebase_history_ea(meta.get("cave_start"), stored_imagebase)
    owner_ea = _rebase_history_ea(meta.get("owner_ea") or meta.get("start_ea"), stored_imagebase)
    if cave_start is None or owner_ea is None:
        return

    owner = ida_funcs.get_func(owner_ea)
    if owner is not None and hasattr(ida_funcs, "remove_func_tail"):
        try:
            ida_funcs.remove_func_tail(owner, cave_start)
        except TypeError:
            try:
                chunk = ida_funcs.get_fchunk(cave_start)
                if chunk is not None:
                    ida_funcs.remove_func_tail(owner, chunk)
            except Exception:
                pass
        except Exception:
            pass

    existing = ida_funcs.get_func(cave_start)
    if existing is not None and existing.start_ea == cave_start:
        try:
            ida_funcs.del_func(cave_start)
        except Exception:
            pass

    try:
        idc.set_name(cave_start, "", idc.SN_NOWARN)
    except Exception:
        pass

    if owner is not None:
        try:
            ida_funcs.reanalyze_function(owner)
        except Exception:
            pass


def _rollback_transaction(entry):
    """Revert one previously recorded plugin transaction."""
    operations = list(entry.get("ops") or [])
    if not operations:
        raise RuntimeError("该补丁事务没有可回撤的字节记录。")

    for operation in reversed(operations):
        _apply_operation_bytes(operation, revert=True)

    if entry.get("kind") == "trampoline":
        _cleanup_trampoline_tail(entry.get("meta") or {})

    ida_auto.auto_wait()
    _mark_transaction_rolled_back(entry["tx_id"])
    _debug_log(
        "history.rollback",
        tx_id=entry["tx_id"],
        kind=entry.get("kind"),
        target_ea="0x%X" % entry.get("target_ea", 0),
        op_count=len(operations),
    )


def _operation_looks_applied(operation, entry_meta=None):
    """Check whether the current database still contains the operation's patched bytes."""
    current_ea = _resolve_operation_ea(operation, entry_meta)
    current_bytes = _read_idb_bytes(current_ea, operation.get("size", 0)).hex()
    return current_bytes.lower() == (operation.get("new_bytes_hex") or "").lower()


def _find_stale_rolled_back_entry(ea=None):
    """Find a rolled-back entry whose bytes still look patched in the current IDB."""
    entries = _load_patch_history()
    for entry in reversed(entries):
        if entry.get("status") != "rolled_back":
            continue
        if ea is not None and not _history_entry_matches_ea(entry, ea):
            continue
        operations = entry.get("ops") or []
        if operations and any(_operation_looks_applied(operation, entry.get("meta") or {}) for operation in operations):
            return entry
    return None


def _rollback_partial_transaction(transaction, applied_count):
    """Best-effort rollback for a transaction that failed before commit."""
    if not transaction or applied_count <= 0:
        return
    operations = list(transaction.get("ops") or [])[:applied_count]
    for operation in reversed(operations):
        _apply_operation_bytes(operation, revert=True)
    if transaction.get("kind") == "trampoline":
        _cleanup_trampoline_tail(transaction.get("meta") or {})
    ida_auto.auto_wait()
    _debug_log(
        "history.partial_rollback",
        tx_id=transaction.get("tx_id"),
        kind=transaction.get("kind"),
        applied_count=applied_count,
    )


def _history_target_ea(ctx):
    """Pick the most relevant EA for a rollback request."""
    items = _selected_items(ctx)
    if items:
        return items[0][0]
    return _current_ea(ctx)


def _describe_history_entry(entry):
    """Build a short user-facing description of one recorded patch transaction."""
    meta = entry.get("meta") or {}
    stored_imagebase = _transaction_imagebase(meta)
    target_ea = _rebase_history_ea(entry.get("target_ea", 0), stored_imagebase)
    cave_start = _rebase_history_ea(meta.get("cave_start"), stored_imagebase)
    parts = [
        "类型: %s" % (entry.get("label") or entry.get("kind") or "unknown"),
        "目标: 0x%X" % (target_ea or 0),
        "操作数: %d" % len(entry.get("ops") or []),
    ]
    if cave_start is not None:
        parts.append("代码洞: 0x%X" % cave_start)
    if meta.get("write_to_file"):
        parts.append("已写回输入文件")
    else:
        parts.append("仅 IDB")
    created_at = entry.get("created_at")
    if created_at:
        parts.append("时间: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_at)))
    return "\n".join(parts)


def _entry_runtime_status(entry):
    """Return the effective runtime status shown in the rollback list."""
    status = (entry.get("status") or "").lower()
    if status == "rolled_back":
        operations = entry.get("ops") or []
        if operations and any(_operation_looks_applied(operation, entry.get("meta") or {}) for operation in operations):
            return "stale"
    return status or "unknown"


def _entry_runtime_status_text(status):
    """Map runtime status to a short Chinese label."""
    mapping = {
        "active": "可回撤",
        "stale": "残留待修复",
        "rolled_back": "已回撤",
        "unknown": "未知",
    }
    return mapping.get(status, status)


def _entry_can_rollback(entry):
    """Return whether the history entry is rollback-able from the list."""
    return _entry_runtime_status(entry) in ("active", "stale")


def _is_file_backed_executable_segment(seg):
    """Return whether the segment is executable and mapped to the input file."""
    if seg is None:
        return False
    if not (getattr(seg, "perm", 0) & ida_segment.SEGPERM_EXEC):
        return False
    return _ea_file_offset(seg.start_ea) is not None


def _is_file_cave_byte(ea):
    """Return whether the byte is an unknown filler byte suitable for a file cave."""
    if _ea_file_offset(ea) is None:
        return False
    flags = ida_bytes.get_flags(ea)
    if not ida_bytes.is_unknown(flags):
        return False
    value = ida_bytes.get_byte(ea)
    return value in FILE_CAVE_FILL_BYTES


def _file_cave_candidates(preferred_ea=None):
    """Yield executable file-backed segments, preferring the segment near `preferred_ea`."""
    segments = []
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if _is_file_backed_executable_segment(seg):
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


def _find_file_code_cave(required_size, preferred_ea=None, alignment=PATCH_STUB_ALIGN):
    """Find a file-backed executable code cave made of unknown filler bytes."""
    if required_size <= 0:
        raise RuntimeError("无效的代码洞大小: %d" % required_size)

    for seg in _file_cave_candidates(preferred_ea):
        current = seg.start_ea
        while current < seg.end_ea:
            while current < seg.end_ea and not _is_file_cave_byte(current):
                current += 1
            run_start = current
            while current < seg.end_ea and _is_file_cave_byte(current):
                current += 1
            run_end = current
            if run_end <= run_start:
                continue
            cave_start = _align_up(run_start, alignment)
            if cave_start + required_size <= run_end:
                _debug_log(
                    "file_cave.find",
                    segment=ida_segment.get_segm_name(seg),
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


def _open_input_pe():
    """Open the current input file as a PE image."""
    pefile = _load_pefile_module()
    if pefile is None:
        raise RuntimeError("未找到 `pefile` 模块，无法操作 PE 节表。")

    path = _input_file_path()
    if not path:
        raise RuntimeError("当前 IDB 没有关联输入文件。")
    if not os.path.isfile(path):
        raise RuntimeError("输入文件不存在: %s" % path)

    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as exc:
        raise RuntimeError("当前输入文件不是受支持的 PE 文件: %s" % exc)
    return pe, path


def _pe_section_name(section):
    """Return a PE section name as text."""
    raw = bytes(section.Name).split(b"\x00", 1)[0]
    try:
        return raw.decode("ascii", errors="ignore")
    except Exception:
        return ""


def _pe_header_room_end(pe):
    """Return the end offset of the PE headers area available for section headers."""
    positive_raw = [section.PointerToRawData for section in pe.sections if section.PointerToRawData]
    if positive_raw:
        return min(positive_raw)
    return pe.OPTIONAL_HEADER.SizeOfHeaders


def _pe_last_raw_end(pe):
    """Return the highest raw file end among PE sections."""
    ends = [section.PointerToRawData + section.SizeOfRawData for section in pe.sections if section.SizeOfRawData]
    return max(ends) if ends else pe.OPTIONAL_HEADER.SizeOfHeaders


def _pe_last_virtual_end(pe):
    """Return the highest RVA end among PE sections."""
    ends = []
    for section in pe.sections:
        span = max(section.Misc_VirtualSize, section.SizeOfRawData)
        ends.append(section.VirtualAddress + span)
    return max(ends) if ends else _align_up(pe.OPTIONAL_HEADER.SizeOfHeaders, pe.OPTIONAL_HEADER.SectionAlignment)


def _pe_patch_section_info(required_size=0):
    """Plan the dedicated file-backed patch section without mutating the file."""
    pe, path = _open_input_pe()
    file_align = max(1, int(pe.OPTIONAL_HEADER.FileAlignment))
    section_align = max(1, int(pe.OPTIONAL_HEADER.SectionAlignment))
    imagebase = ida_nalt.get_imagebase()
    required_size = max(0, int(required_size))

    existing = None
    for section in pe.sections:
        if _pe_section_name(section) == PATCH_FILE_SECTION_NAME:
            existing = section
            break

    if existing is not None:
        info = {
            "path": path,
            "pe": pe,
            "exists": True,
            "section": existing,
            "section_name": PATCH_FILE_SECTION_NAME,
            "header_offset": existing.get_file_offset(),
            "raw_ptr": int(existing.PointerToRawData),
            "raw_size": int(existing.SizeOfRawData),
            "virtual_size": int(existing.Misc_VirtualSize),
            "rva": int(existing.VirtualAddress),
            "ea_start": imagebase + int(existing.VirtualAddress),
            "ea_end": imagebase + int(existing.VirtualAddress) + int(existing.SizeOfRawData),
            "file_align": file_align,
            "section_align": section_align,
            "num_sections_offset": pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"),
            "size_image_offset": pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
            "size_code_offset": pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfCode"),
            "characteristics": int(existing.Characteristics),
        }
        raw_end = existing.PointerToRawData + existing.SizeOfRawData
        virt_end = existing.VirtualAddress + max(existing.Misc_VirtualSize, existing.SizeOfRawData)
        info["can_grow"] = (
            raw_end == _pe_last_raw_end(pe)
            and virt_end == _pe_last_virtual_end(pe)
        )
        return info

    reserve_virtual = max(PATCH_SEGMENT_DEFAULT_SIZE, required_size + 0x100)
    reserve_raw = _align_up(reserve_virtual, file_align)
    last_header_offset = pe.sections[-1].get_file_offset() if pe.sections else (
        pe.DOS_HEADER.e_lfanew
        + 4
        + pe.FILE_HEADER.sizeof()
        + pe.FILE_HEADER.SizeOfOptionalHeader
        - 40
    )
    new_header_offset = last_header_offset + 40
    new_rva = _align_up(_pe_last_virtual_end(pe), section_align)
    new_raw_ptr = _align_up(max(os.path.getsize(path), _pe_last_raw_end(pe)), file_align)
    return {
        "path": path,
        "pe": pe,
        "exists": False,
        "section": None,
        "section_name": PATCH_FILE_SECTION_NAME,
        "header_offset": new_header_offset,
        "raw_ptr": new_raw_ptr,
        "raw_size": reserve_raw,
        "virtual_size": reserve_virtual,
        "rva": new_rva,
        "ea_start": imagebase + new_rva,
        "ea_end": imagebase + new_rva + reserve_raw,
        "file_align": file_align,
        "section_align": section_align,
        "num_sections_offset": pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"),
        "size_image_offset": pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
        "size_code_offset": pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfCode"),
        "characteristics": PE_SECTION_CHARACTERISTICS_RX,
        "can_add": (new_header_offset + 40) <= _pe_header_room_end(pe),
    }


def _write_zero_fill(fh, start_offset, end_offset):
    """Fill the given file range with zero bytes."""
    if end_offset <= start_offset:
        return
    fh.seek(start_offset)
    fh.write(b"\x00" * (end_offset - start_offset))


def _ensure_file_length(path, end_offset):
    """Extend the file with zeros up to `end_offset` bytes."""
    current_size = os.path.getsize(path)
    if current_size >= end_offset:
        return
    with open(path, "r+b") as fh:
        _write_zero_fill(fh, current_size, end_offset)


def _create_pe_patch_section(required_size):
    """Create a dedicated executable PE section for file-backed trampolines."""
    info = _pe_patch_section_info(required_size)
    if info["exists"]:
        return info
    if not info.get("can_add"):
        raise RuntimeError(
            "PE 节表没有足够空间，无法新建文件补丁节 `%s`。"
            % PATCH_FILE_SECTION_NAME
        )

    path = info["path"]
    pe = info["pe"]
    section_name = info["section_name"].encode("ascii", errors="ignore")[:8].ljust(8, b"\x00")
    end_offset = info["raw_ptr"] + info["raw_size"]
    _ensure_file_length(path, end_offset)

    with open(path, "r+b") as fh:
        fh.seek(info["header_offset"])
        fh.write(
            struct.pack(
                "<8sIIIIIIHHI",
                section_name,
                info["virtual_size"],
                info["rva"],
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
        fh.write(struct.pack("<H", pe.FILE_HEADER.NumberOfSections + 1))
        fh.seek(info["size_image_offset"])
        fh.write(
            struct.pack(
                "<I",
                _align_up(info["rva"] + info["virtual_size"], info["section_align"]),
            )
        )
        try:
            fh.seek(info["size_code_offset"])
            fh.write(struct.pack("<I", pe.OPTIONAL_HEADER.SizeOfCode + info["raw_size"]))
        except Exception:
            pass

    _debug_log(
        "pe_patch_section.create",
        path=path,
        section=info["section_name"],
        raw_ptr="0x%X" % info["raw_ptr"],
        raw_size="0x%X" % info["raw_size"],
        rva="0x%X" % info["rva"],
    )
    return _pe_patch_section_info(required_size)


def _extend_pe_patch_section(required_size):
    """Extend the dedicated PE patch section when more raw bytes are needed."""
    info = _pe_patch_section_info(required_size)
    if not info["exists"]:
        return _create_pe_patch_section(required_size)
    if info["raw_size"] >= required_size:
        return info
    if not info.get("can_grow"):
        raise RuntimeError(
            "现有文件补丁节 `%s` 不是最后一个节，无法自动扩展。"
            % info["section_name"]
        )

    path = info["path"]
    pe = info["pe"]
    new_virtual_size = max(info["virtual_size"], required_size + 0x100, PATCH_SEGMENT_DEFAULT_SIZE)
    new_raw_size = _align_up(new_virtual_size, info["file_align"])
    end_offset = info["raw_ptr"] + new_raw_size
    _ensure_file_length(path, end_offset)

    with open(path, "r+b") as fh:
        fh.seek(info["section"].get_field_absolute_offset("Misc_VirtualSize"))
        fh.write(struct.pack("<I", new_virtual_size))
        fh.seek(info["section"].get_field_absolute_offset("SizeOfRawData"))
        fh.write(struct.pack("<I", new_raw_size))
        fh.seek(info["section"].get_field_absolute_offset("Characteristics"))
        fh.write(struct.pack("<I", PE_SECTION_CHARACTERISTICS_RX))
        fh.seek(info["size_image_offset"])
        fh.write(
            struct.pack(
                "<I",
                _align_up(info["rva"] + new_virtual_size, info["section_align"]),
            )
        )
        try:
            delta = new_raw_size - info["raw_size"]
            fh.seek(info["size_code_offset"])
            fh.write(struct.pack("<I", pe.OPTIONAL_HEADER.SizeOfCode + delta))
        except Exception:
            pass

    _debug_log(
        "pe_patch_section.extend",
        path=path,
        section=info["section_name"],
        old_raw_size="0x%X" % info["raw_size"],
        new_raw_size="0x%X" % new_raw_size,
    )
    return _pe_patch_section_info(required_size)


def _segment_perms_from_chars(characteristics):
    """Convert PE section characteristics into IDA segment permissions."""
    perms = 0
    if characteristics & 0x40000000:
        perms |= ida_segment.SEGPERM_READ
    if characteristics & 0x80000000:
        perms |= ida_segment.SEGPERM_WRITE
    if characteristics & 0x20000000:
        perms |= ida_segment.SEGPERM_EXEC
    return perms


def _sync_file_patch_segment_to_idb(info):
    """Create or refresh the IDA segment that mirrors the file-backed patch section."""
    seg = ida_segment.getseg(info["ea_start"])
    if seg is None:
        if not idc.add_segm_ex(
            info["ea_start"],
            info["ea_start"] + info["raw_size"],
            0,
            _patch_segment_bitness(),
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
    ida_segment.set_segm_addressing(seg, _patch_segment_bitness())
    seg.perm = _segment_perms_from_chars(info["characteristics"])
    ida_segment.update_segm(seg)
    ida_segment.set_segment_cmt(
        seg,
        "ida_patch_pro file-backed patch section. 此段已同步到输入文件，可直接运行/调试。",
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
    return ida_segment.getseg(info["ea_start"])


def _prepare_file_patch_segment(required_size, apply_changes=False):
    """Plan or ensure the dedicated file-backed patch section."""
    info = _pe_patch_section_info(required_size)
    if apply_changes:
        info = _extend_pe_patch_section(required_size)
    elif info["exists"] and _find_segment_by_name(info["section_name"], file_backed=True) is None:
        info["segment"] = _sync_file_patch_segment_to_idb(info)

    if apply_changes or info.get("segment") is not None:
        info["segment"] = _sync_file_patch_segment_to_idb(info)
    else:
        info["segment"] = _find_segment_by_name(info["section_name"], file_backed=True)
    return info


def _align_up(value, alignment):
    """Round a value up to the next multiple of `alignment`."""
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def _get_original_instruction_text(ea):
    """Return the disassembly text shown by IDA for the given address."""
    text = idc.GetDisasm(ea) or ""
    return text.strip()


def _sanitize_asm_line(text):
    """Strip trailing IDA comments so only pure assembly text remains."""
    text = (text or "").strip()
    if not text:
        return ""

    cut = len(text)
    for marker in (";", "|"):
        index = text.find(marker)
        if index != -1:
            cut = min(cut, index)
    return text[:cut].strip()


def _get_original_instruction_bytes(ea):
    """Read the original instruction bytes from the database."""
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        return b""
    buf = ida_bytes.get_bytes(ea, size)
    return bytes(buf) if buf else b""


def _get_original_entries(ctx):
    """Build metadata for each selected instruction line."""
    entries = []
    for ea, _ in _selected_items(ctx):
        text = _get_original_instruction_text(ea)
        asm = _sanitize_asm_line(text)
        entries.append(
            {
                "ea": ea,
                "text": text,
                "asm": asm,
                "bytes": _get_original_instruction_bytes(ea),
                "operand_infos": _build_operand_infos(ea, asm),
            }
        )
    return entries


def _get_entries_for_range(start_ea, size):
    """Build instruction entries for a contiguous range."""
    end_ea = start_ea + size
    entries = []
    current = start_ea
    while current < end_ea:
        item_size = ida_bytes.get_item_size(current)
        if item_size <= 0:
            item_size = 1
        text = _get_original_instruction_text(current)
        asm = _sanitize_asm_line(text)
        entries.append(
            {
                "ea": current,
                "text": text,
                "asm": asm,
                "bytes": _get_original_instruction_bytes(current),
                "operand_infos": _build_operand_infos(current, asm),
            }
        )
        current += item_size
    return entries


def _join_entry_asm_lines(entries):
    """Join selected instruction lines into the editable assembly text."""
    return "\n".join(entry["asm"] for entry in entries if entry["asm"])


def _build_preview_infos_from_entries(entries):
    """Convert original instruction entries into preview-style structures."""
    infos = []
    for entry in entries:
        if entry["asm"]:
            infos.append({"line": entry["asm"], "bytes": entry["bytes"], "note": None})
    return infos


def _strip_size_prefix(op):
    """Remove `byte ptr`/`dword ptr`-style prefixes from an operand string."""
    return re.sub(
        r"(?i)\b(?:byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte)\s+ptr\b\s*",
        "",
        op.strip(),
    ).strip()


def _split_size_prefix(op):
    """Split an operand into explicit size prefix and core operand body."""
    stripped = op.strip()
    m = re.match(
        r"(?is)^((?:byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte)\s+ptr)\s+(.*)$",
        stripped,
    )
    if not m:
        return "", stripped
    return m.group(1), m.group(2).strip()


def _normalize_mem_operand(op):
    """Normalize a memory operand so equivalent spellings compare equal."""
    op = _strip_size_prefix(op).lower()
    return re.sub(r"\s+", "", op)


def _size_keyword_from_size(size):
    """Map a byte width to an assembler size keyword."""
    mapping = {
        1: "byte",
        2: "word",
        4: "dword",
        8: "qword",
        10: "tbyte",
        16: "xmmword",
        32: "ymmword",
        64: "zmmword",
    }
    return mapping.get(size)


def _decoded_operand_size_keyword(ea, index, operand_text=""):
    """Try to infer an operand width from the decoded instruction metadata."""
    explicit = _infer_operand_size_keyword(operand_text)
    if explicit:
        return explicit

    try:
        insn = idautils.DecodeInstruction(ea)
    except Exception:
        insn = None
    if not insn:
        return None

    op = None
    ops = getattr(insn, "ops", None)
    if ops is not None:
        try:
            if 0 <= index < len(ops):
                op = ops[index]
        except Exception:
            op = None
    if op is None:
        op = getattr(insn, "Op%d" % (index + 1), None)
    if op is None:
        return None

    dtype = getattr(op, "dtype", None)
    if dtype is None:
        dtype = getattr(op, "dtyp", None)
    if dtype is None:
        return None

    try:
        size = ida_ua.get_dtype_size(dtype)
    except Exception:
        size = None

    if not size:
        fallback_sizes = {
            getattr(ida_ua, "dt_byte", None): 1,
            getattr(ida_ua, "dt_word", None): 2,
            getattr(ida_ua, "dt_dword", None): 4,
            getattr(ida_ua, "dt_float", None): 4,
            getattr(ida_ua, "dt_double", None): 8,
            getattr(ida_ua, "dt_qword", None): 8,
            getattr(ida_ua, "dt_byte16", None): 16,
            getattr(ida_ua, "dt_byte32", None): 32,
            getattr(ida_ua, "dt_byte64", None): 64,
            getattr(ida_ua, "dt_tbyte", None): 10,
        }
        size = fallback_sizes.get(dtype)

    return _size_keyword_from_size(size)


def _pointer_bits():
    """Return the current database pointer width."""
    return 64 if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else 32


def _sign_extend(value, bits):
    """Interpret the given integer as a signed value of `bits` width."""
    if value is None:
        return None
    mask = (1 << bits) - 1
    value &= mask
    sign_bit = 1 << (bits - 1)
    if value & sign_bit:
        value -= 1 << bits
    return value


def _format_hex_literal(value):
    """Format an integer as IDA-style hexadecimal text."""
    if value == 0:
        return "0"
    digits = "%X" % value
    if digits[0] in "ABCDEF":
        digits = "0" + digits
    return digits + "h"


def _is_registerish_mem_term(token, arch_key):
    """Check whether a memory term looks like a register/index component."""
    token = token.strip().lower()
    if not token:
        return False

    token = token.replace(" ", "")
    if token.startswith("-"):
        token = token[1:]
    if "*" in token:
        token = token.split("*", 1)[0]
    if ":" in token:
        token = token.rsplit(":", 1)[-1]

    return _register_hint(token, arch_key) is not None


def _rebuild_stack_operand_text(op_text, disp_value, arch_key):
    """Rewrite IDA stack-var text like `[rsp+198h+var_158]` into real offsets."""
    core = _strip_size_prefix(op_text)
    m = re.match(r"(?is)^(?P<prefix>[^[]*?)(?P<body>\[[^]]*\])(?P<suffix>.*)$", core)
    if not m:
        return core

    prefix = m.group("prefix").strip()
    body = m.group("body")[1:-1]
    suffix = m.group("suffix").strip()

    parts = []
    for match in re.finditer(r"([+-]?)\s*([^+-]+)", body):
        sign = match.group(1) or "+"
        term = match.group(2).strip()
        if _is_registerish_mem_term(term, arch_key):
            parts.append((sign, term))

    disp_bits = 32 if arch_key == "x86/x64" else _pointer_bits()
    disp = _sign_extend(int(disp_value), disp_bits)
    if disp is None:
        disp = 0

    body_text = ""
    for index, (sign, term) in enumerate(parts):
        if index == 0:
            body_text = term if sign != "-" else "-" + term
        else:
            body_text += ("-" if sign == "-" else "+") + term

    if disp != 0 or not body_text:
        disp_text = _format_hex_literal(abs(disp))
        if body_text:
            body_text += ("-" if disp < 0 else "+") + disp_text
        else:
            body_text = ("-" if disp < 0 else "") + disp_text

    result = "[%s]" % body_text
    if prefix:
        result = "%s%s" % (prefix, result)
    if suffix:
        result = "%s%s" % (result, suffix)
    return result


def _build_operand_infos(ea, asm):
    """Collect per-operand display text, rewritten forms, and inferred size hints."""
    arch_key = _processor_key()
    flags = ida_bytes.get_flags(ea)
    _, operands = _split_operands(asm)
    infos = []

    for index, operand in enumerate(operands):
        asm_operand = operand
        if (
            arch_key == "x86/x64"
            and "[" in operand
            and "]" in operand
            and ida_bytes.is_stkvar(flags, index)
        ):
            disp_value = idc.get_operand_value(ea, index)
            asm_operand = _rebuild_stack_operand_text(operand, disp_value, arch_key)
        size_keyword = _decoded_operand_size_keyword(ea, index, operand)
        infos.append(
            {
                "index": index,
                "display": operand,
                "normalized": _normalize_mem_operand(operand),
                "asm_operand": asm_operand,
                "normalized_asm": _normalize_mem_operand(asm_operand),
                "size_keyword": size_keyword,
            }
        )
        if asm_operand != operand or size_keyword:
            _debug_log(
                "operand_info",
                ea="0x%X" % ea,
                index=index,
                display=operand,
                asm_operand=asm_operand,
                size_keyword=size_keyword,
            )
    return infos


def _rewrite_line_for_assembly(line, arch_key, original_entry=None):
    """Rewrite user text into a more assembler-friendly form before assembly."""
    if not original_entry:
        return line

    mnem, operands = _split_operands(line)
    if not mnem or not operands:
        return line

    operand_infos = original_entry.get("operand_infos") or []
    if not operand_infos:
        return line

    rewritten = []
    for operand in operands:
        size_prefix, core = _split_size_prefix(operand)
        normalized = _normalize_mem_operand(core)
        replacement = None
        for info in operand_infos:
            if info.get("normalized") == normalized and info.get("asm_operand"):
                replacement = info["asm_operand"]
                break
        if replacement is None:
            rewritten.append(operand)
            continue
        if size_prefix:
            rewritten.append("%s %s" % (size_prefix, replacement))
        else:
            rewritten.append(replacement)

    result = "%s %s" % (mnem, ", ".join(rewritten))
    if result != line:
        _debug_log(
            "rewrite_line",
            ea="0x%X" % original_entry.get("ea", 0) if original_entry.get("ea") is not None else "",
            original=line,
            rewritten=result,
        )
    return result


def _infer_operand_size_keyword(op):
    """Infer operand width keyword such as byte/dword/qword from text."""
    lower = op.strip().lower()
    for prefix in ("byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword", "tbyte"):
        if re.search(r"(?i)\b%s\s+ptr\b" % prefix, lower):
            return prefix

    reg = lower
    if reg in ("al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "bpl", "spl"):
        return "byte"
    if re.fullmatch(r"r(1[0-5]|[8-9])b", reg):
        return "byte"
    if reg in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        return "word"
    if re.fullmatch(r"r(1[0-5]|[8-9])w", reg):
        return "word"
    if reg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        return "dword"
    if re.fullmatch(r"r(1[0-5]|[8-9])d", reg):
        return "dword"
    if reg in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
        return "qword"
    if re.fullmatch(r"r(1[0-5]|[8-9])", reg):
        return "qword"
    if re.fullmatch(r"xmm([0-9]|1[0-5])", reg):
        return "xmmword"
    if re.fullmatch(r"ymm([0-9]|1[0-5])", reg):
        return "ymmword"
    if re.fullmatch(r"zmm([0-9]|1[0-5]|2[0-9]|3[01])", reg):
        return "zmmword"
    return None


def _infer_memory_size_keyword(original_entry, current_dst):
    """Infer the required `ptr` size for a memory-destination rewrite."""
    if not original_entry:
        return None

    wanted = _normalize_mem_operand(current_dst)
    matched_sizes = []
    for info in original_entry.get("operand_infos") or []:
        size_keyword = info.get("size_keyword")
        if not size_keyword:
            continue
        candidates = set()
        normalized = info.get("normalized")
        if normalized:
            candidates.add(normalized)
        normalized_asm = info.get("normalized_asm")
        if normalized_asm:
            candidates.add(normalized_asm)
        asm_operand = info.get("asm_operand")
        if asm_operand:
            candidates.add(_normalize_mem_operand(asm_operand))
        if wanted in candidates:
            matched_sizes.append(size_keyword)

    unique_sizes = []
    seen_sizes = set()
    for size_keyword in matched_sizes:
        if size_keyword in seen_sizes:
            continue
        seen_sizes.add(size_keyword)
        unique_sizes.append(size_keyword)
    if len(unique_sizes) == 1:
        return unique_sizes[0]

    original_asm = original_entry.get("asm", "")
    _, ops = _split_operands(original_asm)
    if not ops:
        return unique_sizes[0] if unique_sizes else None
    mem_ops = [op for op in ops if "[" in op and "]" in op]
    if not mem_ops:
        return unique_sizes[0] if unique_sizes else None

    chosen = None
    for op in mem_ops:
        if _normalize_mem_operand(op) == wanted:
            chosen = op
            break
    if chosen is None and len(mem_ops) == 1:
        chosen = mem_ops[0]
    if chosen is None:
        return None

    explicit = _infer_operand_size_keyword(chosen)
    if explicit:
        return explicit

    for op in ops:
        if op == chosen:
            continue
        inferred = _infer_operand_size_keyword(op)
        if inferred:
            return inferred

    mnem = _extract_mnemonic(original_asm)
    if mnem in ("movaps", "movups", "movdqa", "movdqu", "pxor", "xorps"):
        return "xmmword"
    return unique_sizes[0] if unique_sizes else None


def _first_nonempty_line(text):
    """Return the first non-empty line from a multi-line editor string."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _extract_mnemonic(text):
    """Extract the mnemonic from the first meaningful line of assembly text."""
    line = _sanitize_asm_line(_first_nonempty_line(text))
    if not line:
        return ""
    tokens = line.split()
    if not tokens:
        return ""
    first = tokens[0].lower()
    if first in ("rep", "repe", "repz", "repne", "repnz", "lock") and len(tokens) >= 2:
        second = tokens[1].lower()
        combined = "%s %s" % (first, second)
        if combined in MNEMONIC_HINTS:
            return combined
        if second in MNEMONIC_HINTS:
            return second
        return combined
    return first


def _mnemonic_hint_text(mnem):
    """Return a mnemonic explanation, including common instruction families."""
    if not mnem:
        return "该助记符暂无内置说明。"
    if mnem in MNEMONIC_HINTS:
        return MNEMONIC_HINTS[mnem]
    if re.fullmatch(r"j[a-z]{1,4}", mnem):
        return "条件跳转指令。根据标志寄存器决定是否跳转，常与 `cmp/test` 配合使用。"
    if re.fullmatch(r"set[a-z]{1,4}", mnem):
        return "条件置位指令。根据标志位把目标字节写成 0 或 1，常用于把条件判断结果落到寄存器。"
    if re.fullmatch(r"cmov[a-z]{1,4}", mnem):
        return "条件移动指令。仅当条件满足时才移动源操作数到目标，常用于减少分支。"
    return "该助记符暂无内置说明。"


def _extract_registers(text, arch_key):
    """Extract registers mentioned in the current line for hint display."""
    line = _first_nonempty_line(text).lower()
    if not line:
        return []

    found = []
    seen = set()
    for token in re.findall(r"\$[a-z0-9]+|[a-z][a-z0-9()]*", line):
        if token in seen:
            continue
        if _register_hint(token, arch_key):
            found.append(token)
            seen.add(token)
    return found


def _split_operands(text):
    """Split a single instruction into mnemonic and operand list."""
    line = _sanitize_asm_line(_first_nonempty_line(text))
    if not line:
        return "", []

    code = line.strip()
    parts = code.split(None, 1)
    if not parts:
        return "", []
    if len(parts) == 1:
        return parts[0].lower(), []

    ops = []
    current = []
    depth = 0
    for ch in parts[1]:
        if ch in "[({":
            depth += 1
        elif ch in "])}" and depth > 0:
            depth -= 1

        if ch == "," and depth == 0:
            operand = "".join(current).strip()
            if operand:
                ops.append(operand)
            current = []
            continue
        current.append(ch)

    operand = "".join(current).strip()
    if operand:
        ops.append(operand)
    return parts[0].lower(), ops


def _is_zero_literal(text):
    """Return whether the text represents zero in decimal or hex form."""
    value = text.strip().lower().replace("_", "")
    if not value:
        return False
    if value in ("0", "+0", "-0", "0h", "+0h", "-0h", "0x0", "+0x0", "-0x0"):
        return True
    if value.startswith(("0x", "+0x", "-0x")):
        value = value.replace("+", "").replace("-", "")
        return value[2:] and set(value[2:]) == {"0"}
    if value.endswith("h"):
        value = value[:-1].replace("+", "").replace("-", "")
        return value and set(value) == {"0"}
    return value.replace("+", "").replace("-", "").isdigit() and set(value.replace("+", "").replace("-", "")) == {"0"}


def _is_immediate_literal(text):
    """Return whether the text looks like an immediate literal value."""
    value = text.strip().lower().replace("_", "")
    if not value:
        return False
    if value.startswith(("0x", "+0x", "-0x")):
        body = value.replace("+", "").replace("-", "")[2:]
        return bool(body) and all(ch in "0123456789abcdef" for ch in body)
    if value.endswith("h"):
        body = value[:-1].replace("+", "").replace("-", "")
        return bool(body) and all(ch in "0123456789abcdef" for ch in body)
    value = value.replace("+", "").replace("-", "")
    return value.isdigit()


def _parse_immediate_value(text):
    """Parse a decimal/hex literal and return its integer value."""
    value = text.strip().lower().replace("_", "")
    if not value:
        return None
    sign = 1
    if value[0] == "+":
        value = value[1:]
    elif value[0] == "-":
        sign = -1
        value = value[1:]
    if not value:
        return None
    try:
        if value.startswith("0x"):
            return sign * int(value, 16)
        if value.endswith("h"):
            return sign * int(value[:-1], 16)
        return sign * int(value, 10)
    except ValueError:
        return None


def _strip_symbol_operand_prefixes(text):
    """Normalize a simple code/data operand before trying IDA name resolution."""
    value = (text or "").strip()
    if not value:
        return ""
    value = re.sub(r"(?i)\b(offset|short|near|far|ptr|large|rel)\b", " ", value)
    value = " ".join(value.split())
    if ":" in value and "[" not in value and "]" not in value:
        value = value.split(":", 1)[1].strip()
    return value


def _resolve_symbol_operand_ea(text, arch_key):
    """Resolve a simple symbol-like operand to an EA when possible."""
    operand = _strip_symbol_operand_prefixes(text)
    if not operand:
        return None
    if any(ch in operand for ch in "[]()*"):
        return None
    if _is_immediate_literal(operand):
        return None
    if _register_hint(operand, arch_key):
        return None
    ea = idc.get_name_ea_simple(operand)
    if ea != ida_idaapi.BADADDR:
        return ea

    for op in ("+", "-"):
        if op not in operand:
            continue
        base_text, offset_text = operand.rsplit(op, 1)
        base_text = base_text.strip()
        offset_text = offset_text.strip()
        if not base_text or not offset_text or not _is_immediate_literal(offset_text):
            continue
        if _register_hint(base_text, arch_key):
            continue
        base_ea = idc.get_name_ea_simple(base_text)
        if base_ea == ida_idaapi.BADADDR:
            continue
        offset_value = _parse_immediate_value(offset_text)
        if offset_value is None:
            continue
        return base_ea + offset_value if op == "+" else base_ea - offset_value

    return None


def _resolve_direct_branch_target_ea(text, arch_key):
    """Resolve a direct `call/jmp` operand into an absolute EA when possible."""
    target_ea = _resolve_symbol_operand_ea(text, arch_key)
    if target_ea is not None:
        return target_ea

    operand = _strip_symbol_operand_prefixes(text)
    if not operand:
        return None
    if any(ch in operand for ch in "[]()*"):
        return None
    if _register_hint(operand, arch_key):
        return None
    return _parse_immediate_value(operand)


def _encode_rel32_branch(ea, mnem, target_ea, arch_key):
    """Encode a direct x86/x64 `call/jmp` as rel32 without using an assembler."""
    if arch_key != "x86/x64" or mnem not in ("call", "jmp") or target_ea is None:
        return None

    rel = int(target_ea) - int(ea + 5)
    if rel < -0x80000000 or rel > 0x7FFFFFFF:
        return None

    opcode = 0xE8 if mnem == "call" else 0xE9
    return bytes((opcode,)) + struct.pack("<i", rel)


def _assemble_direct_branch_bytes(ea, text, arch_key):
    """Fallback to manual rel32 encoding for simple direct `call/jmp` targets."""
    mnem, operands = _split_operands(text)
    if len(operands) < 1:
        return None, None

    target_ea = _resolve_direct_branch_target_ea(operands[0], arch_key)
    branch_bytes = _encode_rel32_branch(ea, mnem, target_ea, arch_key)
    if branch_bytes is None:
        return None, None

    return (
        branch_bytes,
        "兼容模板: 直接按 rel32 计算 `%s` 目标位移并编码，绕过汇编器的符号解析限制。"
        % mnem,
    )


def _is_64bit_program():
    """Return whether the current database is 64-bit."""
    return bool(idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT)


def _build_rip_relative_lea_candidate(ea, dst, target_ea, arch_key):
    """Build a position-independent `lea reg, [rip+disp]` candidate for x64."""
    if arch_key != "x86/x64" or not _is_64bit_program():
        return None

    dst = (dst or "").strip()
    if not dst:
        return None

    probe = "lea %s, [rip]" % dst
    probe_bytes = _try_assemble_line_keystone(ea, probe, arch_key) or _try_assemble_line(ea, probe)
    if not probe_bytes:
        probe = "lea %s, [rip+0]" % dst
        probe_bytes = _try_assemble_line_keystone(ea, probe, arch_key) or _try_assemble_line(ea, probe)
    if not probe_bytes:
        return None

    disp = target_ea - (ea + len(probe_bytes))
    if disp < -0x80000000 or disp > 0x7FFFFFFF:
        return None

    if disp == 0:
        return "lea %s, [rip]" % dst
    if disp > 0:
        return "lea %s, [rip+0x%X]" % (dst, disp)
    return "lea %s, [rip-0x%X]" % (dst, -disp)


def _canonical_x64_reg(text):
    """Map partial x64 register views back to their 64-bit canonical register."""
    reg = text.strip().lower()
    mapping = {
        "rax": "rax", "eax": "rax", "ax": "rax", "ah": "rax", "al": "rax",
        "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bh": "rbx", "bl": "rbx",
        "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "ch": "rcx", "cl": "rcx",
        "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dh": "rdx", "dl": "rdx",
        "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
        "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
        "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    }
    if reg in mapping:
        return mapping[reg]
    m = re.fullmatch(r"r(1[0-5]|[8-9])(?:d|w|b)?", reg)
    if m:
        return "r%s" % m.group(1)
    return None


def _to_x64_reg32(text):
    """Map an x64 register to its 32-bit form for shorter rewrite templates."""
    base = _canonical_x64_reg(text)
    if not base:
        return None
    mapping = {
        "rax": "eax",
        "rbx": "ebx",
        "rcx": "ecx",
        "rdx": "edx",
        "rsi": "esi",
        "rdi": "edi",
        "rbp": "ebp",
        "rsp": "esp",
    }
    if base in mapping:
        return mapping[base]
    m = re.fullmatch(r"r(1[0-5]|[8-9])", base)
    if m:
        return "r%sd" % m.group(1)
    return None


def _fallback_assembly_candidates(ea, line, arch_key, original_entry=None):
    """Generate compatibility rewrites when the original text may fail to assemble."""
    mnem, operands = _split_operands(line)
    if not mnem:
        return []

    candidates = []
    if arch_key == "x86/x64" and len(operands) >= 1 and mnem in ("call", "jmp"):
        target_ea = _resolve_symbol_operand_ea(operands[0], arch_key)
        if target_ea is not None:
            candidates.append(
                (
                    "%s 0x%X" % (mnem, target_ea),
                    "兼容模板: 将 `%s` 的符号目标改写成绝对地址，避免在代码洞里解析失败。"
                    % mnem,
                )
            )

    if arch_key == "x86/x64" and mnem == "lea" and len(operands) >= 2:
        target_ea = _resolve_symbol_operand_ea(operands[1], arch_key)
        if target_ea is not None:
            rip_candidate = _build_rip_relative_lea_candidate(ea, operands[0], target_ea, arch_key)
            if rip_candidate:
                candidates.append(
                    (
                        rip_candidate,
                        "兼容模板: 将 `lea reg, symbol` 改写成 RIP 相对寻址，避免文件补丁在 ASLR 下失效。"
                    )
                )
            elif not _is_64bit_program():
                candidates.append(
                    (
                        "mov %s, 0x%X" % (operands[0], target_ea),
                        "兼容模板: 将 `lea reg, symbol` 改写成地址立即数加载。仅适合不落盘的临时场景。"
                    )
                )

    if arch_key == "x86/x64" and mnem == "mov" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        dst32 = _to_x64_reg32(dst)
        value = _parse_immediate_value(src)
        if dst32 and value is not None:
            if value == 0:
                candidates.append(
                    (
                        "xor %s, %s" % (dst32, dst32),
                        "兼容模板: 用 `xor %s, %s` 实现清零。"
                        % (dst32, dst32),
                    )
                )
                candidates.append(
                    (
                        "mov %s, 0" % dst32,
                        "兼容模板: 用 `mov %s, 0` 代替 64 位立即数写法。"
                        % dst32,
                    )
                )
            elif 0 <= value <= 0xFFFFFFFF:
                candidates.append(
                    (
                        "mov %s, %s" % (dst32, src),
                        "兼容模板: 用 `mov %s, %s` 代替，它会清零高 32 位。"
                        % (dst32, src),
                    )
                )
        if "[" in dst and "]" in dst and _is_immediate_literal(src):
            size_kw = _infer_memory_size_keyword(original_entry, dst)
            if size_kw in ("byte", "word", "dword", "qword"):
                dst_clean = _strip_size_prefix(dst)
                candidates.append(
                    (
                        "mov %s ptr %s, %s" % (size_kw, dst_clean, src),
                        "兼容模板: 对内存写立即数时自动补上 `%s ptr` 大小限定。"
                        % size_kw,
                    )
                )

    if (
        arch_key == "x86/x64"
        and mnem in ("add", "sub", "and", "or", "xor", "adc", "sbb", "cmp")
        and len(operands) >= 2
    ):
        dst, src = operands[0], operands[1]
        if "[" in dst and "]" in dst and _is_immediate_literal(src):
            size_kw = _infer_memory_size_keyword(original_entry, dst)
            if size_kw in ("byte", "word", "dword", "qword"):
                dst_clean = _strip_size_prefix(dst)
                candidates.append(
                    (
                        "%s %s ptr %s, %s" % (mnem, size_kw, dst_clean, src),
                        "兼容模板: 对内存做 `%s imm` 时自动补上 `%s ptr` 大小限定。"
                        % (mnem, size_kw),
                    )
                )

    if arch_key == "x86/x64" and mnem in ("movaps", "movups", "movdqa", "movdqu") and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        scalar_size = _infer_operand_size_keyword(dst)
        if "[" in dst and "]" in dst and scalar_size in ("byte", "word", "dword", "qword") and _is_immediate_literal(src):
            dst_clean = _strip_size_prefix(dst)
            candidates.append(
                (
                    "mov %s ptr %s, %s" % (scalar_size, dst_clean, src),
                    "兼容模板: `%s` 不能直接把立即数写入内存，已按标量 `mov %s ptr` 重写。"
                    % (mnem, scalar_size),
                )
            )
    return candidates


def _build_template_suggestions(current_text, current_bytes, region_size, arch_key, original_entry=None):
    """Build right-panel rewrite suggestions for the current instruction line."""
    mnem, operands = _split_operands(current_text)
    if not mnem:
        return []

    overflow = current_bytes is not None and len(current_bytes) > region_size
    suggestions = []

    if mnem == "mov" and len(operands) >= 2 and arch_key == "x86/x64":
        dst, src = operands[0], operands[1]
        dst64 = _canonical_x64_reg(dst)
        dst32 = _to_x64_reg32(dst)
        size_kw = _infer_memory_size_keyword(original_entry, dst)

        if dst64 and _is_zero_literal(src):
            if overflow:
                suggestions.append(
                    "长度不够时优先模板: `xor %s, %s`。它能把 `%s` 清零，通常明显短于 `mov %s, 0`。"
                    % (dst32 or dst, dst32 or dst, dst64, dst)
                )
            suggestions.append(
                "固定模板: `xor %s, %s`。这是把寄存器置 0 的首选短写法。"
                % (dst32 or dst, dst32 or dst)
            )
            if dst32:
                suggestions.append(
                    "固定模板: `mov %s, 0`。写 32 位寄存器时会自动清零对应 64 位高半部分。"
                    % dst32
                )
            suggestions.append(
                "如果必须保留 `mov %s, 0` 这种完整写法，请扩大选区或接受继续覆盖后续字节。"
                % dst
            )
            return suggestions

        if dst64 and _is_immediate_literal(src):
            if overflow:
                suggestions.append(
                    "长度不够时可先尝试更短模板: `mov %s, %s`。x64 下写 32 位寄存器会清零高 32 位。"
                    % (dst32 or dst, src)
                )
            if dst32:
                suggestions.append(
                    "固定模板: `mov %s, %s`。适合你只是想把一个立即数放进寄存器且不关心高 32 位原值的场景。"
                    % (dst32, src)
                )
            suggestions.append(
                "如果要把更大的立即数完整写进 `%s`，最稳的方法仍是扩大选区。"
                % dst
            )
            return suggestions

        if dst64 and _canonical_x64_reg(src):
            suggestions.append(
                "寄存器到寄存器的 `mov` 通常已经比较短；如果这里仍超长，更多是当前地址空间不够，建议扩大选区。"
            )
            suggestions.append(
                "如果你的真实目的只是清空 `%s`，可直接改成 `xor %s, %s`。"
                % (dst64, dst32 or dst, dst32 or dst)
            )
            return suggestions

        if "[" in dst and "]" in dst and _is_immediate_literal(src):
            if size_kw in ("byte", "word", "dword", "qword"):
                suggestions.append(
                    "固定模板: `mov %s ptr %s, %s`。对内存写立即数时，通常必须显式写出大小。"
                    % (size_kw, _strip_size_prefix(dst), src)
                )
            else:
                suggestions.append(
                    "对内存写立即数时，通常必须显式写出大小，例如 `mov byte/dword/qword ptr [mem], imm`。"
                )
            return suggestions

        suggestions.append("`mov` 涉及内存寻址时，长度往往由地址编码决定，最直接的办法通常是扩大选区。")
        suggestions.append("如果你只是想把寄存器清零，优先考虑 `xor <reg32>, <reg32>` 这类短模板。")
        return suggestions

    if mnem == "mov" and len(operands) >= 2 and arch_key in ("ARM/Thumb", "AArch64"):
        dst, src = operands[0], operands[1]
        suggestions.append("ARM/AArch64 的 `mov` 长度通常更稳定；若超出范围，多半需要扩大选区而不是换助记符。")
        if _is_zero_literal(src):
            suggestions.append("固定模板: `eor %s, %s, %s`。当你只是想清零寄存器时可作为等价写法。" % (dst, dst, dst))
        return suggestions

    if mnem == "mov" and len(operands) >= 2 and arch_key == "MIPS":
        dst, src = operands[0], operands[1]
        suggestions.append("MIPS 的 `mov/li` 经常是伪指令，可能展开成多条真实指令；超长时应优先检查是否需要扩大选区。")
        if _is_zero_literal(src):
            suggestions.append("固定模板: `move %s, $zero`。当你只是想置零寄存器时可直接使用。" % dst)
        return suggestions

    if mnem == "lea" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        suggestions.append("固定模板: `lea %s, [base+index*scale+disp]`。适合做地址计算，而不是读内存。" % dst)
        suggestions.append("如果你的真实目的其实是取内存里的值，应改用 `mov %s, %s`。" % (dst, src))
        return suggestions

    if mnem == "xor" and len(operands) >= 2:
        left, right = operands[0], operands[1]
        suggestions.append("固定模板: `xor dst, src`。适合做按位异或。")
        if left.lower() == right.lower():
            suggestions.append("当前写法也是经典清零模板: `xor %s, %s`。" % (left, right))
        else:
            suggestions.append("如果你的真实目的只是清零 `%s`，可改成 `xor %s, %s`。" % (left, left, left))
        return suggestions

    if mnem == "add" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        suggestions.append("固定模板: `add %s, %s`。适合给目标加上寄存器或立即数。" % (dst, src))
        suggestions.append("如果你只是想加 1，可考虑 `inc %s`，但要注意它与 `add` 的标志位行为并不完全相同。" % dst)
        return suggestions

    if mnem == "sub" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        suggestions.append("固定模板: `sub %s, %s`。适合从目标减去寄存器或立即数。" % (dst, src))
        suggestions.append("如果你只是想减 1，可考虑 `dec %s`，但要注意它与 `sub` 的标志位行为并不完全相同。" % dst)
        return suggestions

    if mnem == "cmp" and len(operands) >= 2:
        left, right = operands[0], operands[1]
        suggestions.append("固定模板: `cmp %s, %s`。适合做大小/相等比较，然后配合条件跳转。" % (left, right))
        suggestions.append("常见配套模板: `cmp %s, %s` 后接 `jz/jnz/jg/jl/...`。" % (left, right))
        return suggestions

    if mnem == "test" and len(operands) >= 2:
        left, right = operands[0], operands[1]
        suggestions.append("固定模板: `test %s, %s`。适合做按位测试，只更新标志位，不保存结果。" % (left, right))
        suggestions.append("常见零值判断模板: `test reg, reg` 后接 `jz/jnz`。")
        return suggestions

    if mnem in ("jz", "je", "jnz", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "js", "jns") and operands:
        suggestions.append("固定模板: `%s target`。条件跳转通常依赖前面的 `cmp/test` 结果。" % mnem)
        suggestions.append("常见配套模板: 先 `cmp/test`，再 `%s label`。" % mnem)
        return suggestions

    if mnem == "jmp" and operands:
        suggestions.append("固定模板: `jmp target`。无条件跳转会直接改变控制流。")
        suggestions.append("如果目标是寄存器，也可用 `jmp reg` 做间接跳转。")
        return suggestions

    if mnem == "call" and operands:
        suggestions.append("固定模板: `call target`。直接调用函数或子过程。")
        suggestions.append("如果目标在寄存器里，也可用 `call reg`。")
        return suggestions

    if mnem == "push" and operands:
        suggestions.append("固定模板: `push src`。常用于保存寄存器、传参或构造栈数据。")
        if arch_key == "x86/x64":
            suggestions.append("常见配套模板: `push imm` / `pop reg`，可把一个立即数放进寄存器。")
        return suggestions

    if mnem == "pop" and operands:
        suggestions.append("固定模板: `pop dst`。常用于恢复寄存器或从栈中取值。")
        suggestions.append("常见配套模板: `push src` 后接 `pop dst`。")
        return suggestions

    if mnem == "ret":
        suggestions.append("固定模板: `ret`。直接从当前函数返回。")
        suggestions.append("如果调用约定要求回收参数，某些平台会见到 `ret imm`。")
        return suggestions

    if mnem == "nop":
        suggestions.append("固定模板: `nop`。适合补齐长度、屏蔽逻辑或做对齐填充。")
        suggestions.append("如果需要覆盖更长范围，可以连续使用多条 `nop`。")
        return suggestions

    if mnem in ("and", "or") and len(operands) >= 2:
        suggestions.append("固定模板: `%s %s, %s`。适合位运算、掩码处理和标志位修改。" % (mnem, operands[0], operands[1]))
        return suggestions

    if mnem in ("movaps", "movups", "movdqa", "movdqu") and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        vector_dst = _strip_size_prefix(dst)
        suggestions.append(
            "`%s` 只能在向量寄存器和对应内存块之间搬运，不能直接把立即数当源操作数。"
            % mnem
        )
        if "[" in dst and "]" in dst and _is_immediate_literal(src):
            suggestions.append(
                "如果你想把这块 16 字节内存清零，常见模板是 `pxor xmm0, xmm0` 后再 `%s xmmword ptr %s, xmm0`。"
                % (mnem, vector_dst)
            )
            suggestions.append(
                "如果你只是想给其中某个标量槽写入 1，请改用 `mov byte/word/dword/qword ptr %s, 1` 并明确大小。"
                % vector_dst
            )
        return suggestions

    if mnem in ("imul", "mul", "div", "idiv"):
        suggestions.append("这类乘除法指令通常受特定寄存器约束，修改前应先确认调用约定和结果寄存器。")
        if arch_key == "x86/x64":
            suggestions.append("x86/x64 下常见固定模板会隐式使用 `rax/rdx`。")
        return suggestions

    suggestions.append("当前助记符 `%s` 暂无专门模板，但右侧的原机器码、寄存器作用和长度提示仍可作为改写参考。" % mnem)
    return suggestions

    return suggestions


def _length_warning_text(patch_size, region_size, has_selection, start_ea):
    """Return a user-facing summary of length fit or overflow."""
    if patch_size == region_size:
        return "长度匹配当前可覆盖范围。"
    if patch_size < region_size:
        return "新汇编比原范围短 %d bytes，剩余部分会自动补 NOP。" % (region_size - patch_size)

    overflow_end = start_ea + patch_size - 1
    if has_selection:
        return (
            "新汇编超出选区 %d bytes，当前不会允许写入；"
            " 需要扩大选区到至少 0x%X。"
            % (patch_size - region_size, overflow_end)
        )
    return (
        "新汇编超出当前指令 %d bytes，将继续覆盖到 0x%X。"
        % (patch_size - region_size, overflow_end)
    )


def _build_hint_text(original_entries, current_text, preview_bytes, preview_infos, region_size, has_selection, start_ea, arch_key):
    """Assemble the full right-side help panel text."""
    current_lines = [_sanitize_asm_line(line) for line in current_text.splitlines()]
    current_lines = [line for line in current_lines if line]
    preview_infos = preview_infos or []

    line_count = max(len(original_entries), len(current_lines), len(preview_infos), 1)
    lines = []

    if line_count > 1:
        lines.append(
            "原始行数: %d | 当前编辑行数: %d"
            % (len(original_entries), len(current_lines))
        )
        if preview_bytes is not None:
            lines.append("总长度提示: %s" % _length_warning_text(len(preview_bytes), region_size, has_selection, start_ea))
        elif current_text.strip():
            lines.append("总长度提示: 当前输入还无法成功汇编")

    for index in range(line_count):
        original_entry = original_entries[index] if index < len(original_entries) else None
        current_line = current_lines[index] if index < len(current_lines) else ""
        preview_info = preview_infos[index] if index < len(preview_infos) else None

        if lines:
            lines.append("")
        title = "第 %d 行" % (index + 1)
        if original_entry:
            title += " @ 0x%X" % original_entry["ea"]
        lines.append(title)

        if original_entry:
            lines.append("原指令: %s" % (original_entry["text"] or "(unknown)"))
            lines.append("原机器码: %s" % _format_bytes_hex(original_entry["bytes"]))
        else:
            lines.append("原指令: (无)")
            lines.append("原机器码: (none)")

        if current_line:
            lines.append("当前编辑: %s" % current_line)
            if preview_info:
                lines.append("新机器码预览: %s" % _format_bytes_hex(preview_info["bytes"]))
                if preview_info.get("note"):
                    lines.append("兼容说明: %s" % preview_info["note"])
            else:
                lines.append("新机器码预览: 当前输入还无法成功汇编")

        source_text = current_line or (original_entry["asm"] if original_entry else "")
        hint_key = _extract_mnemonic(source_text)
        if hint_key:
            lines.append("指令说明: %s" % _mnemonic_hint_text(hint_key))

        regs = _extract_registers(source_text, arch_key)
        if regs:
            lines.append("寄存器提示:")
            for reg in regs:
                lines.append("%s: %s" % (reg, _register_hint(reg, arch_key) or "暂无说明。"))

        per_line_region = len(original_entry["bytes"]) if original_entry and original_entry["bytes"] else region_size
        per_line_bytes = preview_info["bytes"] if preview_info else None
        suggestions = _build_template_suggestions(source_text, per_line_bytes, per_line_region, arch_key, original_entry)
        if suggestions:
            lines.append("模板建议:")
            for suggestion in suggestions:
                lines.append("- %s" % suggestion)

    return "\n".join(lines)


def _processor_key():
    """Map IDA processor info to the plugin's architecture categories."""
    proc_name = idc.get_inf_attr(idc.INF_PROCNAME)
    is_64bit = bool(idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT)

    if proc_name == "metapc":
        return "x86/x64"
    if proc_name == "ARM":
        return "AArch64" if is_64bit else "ARM/Thumb"
    if proc_name in ("mips", "mipsb", "mipsl"):
        return "MIPS"
    return "x86/x64"


def _try_assemble_line(ea, text):
    """Try assembling one line with IDA's built-in assembler."""
    prev_batch = idc.batch(1)
    try:
        ok, result = idautils.Assemble(ea, text)
    finally:
        idc.batch(prev_batch)

    if ok:
        return bytes(result)
    return None


def _can_try_keystone_on_line(text, arch_key):
    """Check whether a line is simple enough for Keystone fallback assembly."""
    if arch_key != "x86/x64":
        return False

    mnem, operands = _split_operands(text)
    if not mnem:
        return False

    allowed_words = {
        "byte",
        "word",
        "dword",
        "qword",
        "xmmword",
        "ymmword",
        "zmmword",
        "tbyte",
        "ptr",
        "short",
        "near",
        "far",
    }

    for operand in operands:
        scan = operand.lower()
        scan = re.sub(r"(?i)\b0x[0-9a-f]+\b", " ", scan)
        scan = re.sub(r"(?i)\b[0-9][0-9a-f]*h\b", " ", scan)
        scan = re.sub(r"\b\d+\b", " ", scan)
        for token in re.findall(r"\$[a-z_][a-z0-9_]*|[a-z_][a-z0-9_]*", scan):
            if token in allowed_words:
                continue
            if _register_hint(token, arch_key):
                continue
            return False
    return True


def _load_keystone_module():
    """Import Keystone from IDA Python or common Windows Python installs."""
    try:
        import keystone  # type: ignore

        return keystone
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

    for env_name in ("LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name)
        if not base:
            continue
        for root in glob.glob(os.path.join(base, "Python*")):
            add_dir(os.path.join(root, "Lib", "site-packages"))
        for root in glob.glob(os.path.join(base, "Programs", "Python", "Python*")):
            add_dir(os.path.join(root, "Lib", "site-packages"))

    for path in candidates:
        if path not in sys.path:
            sys.path.append(path)
        try:
            import keystone  # type: ignore

            return keystone
        except Exception:
            continue

    return None


def _try_assemble_line_keystone(ea, text, arch_key):
    """Try assembling one line with Keystone, locally or via system Python."""
    if not _can_try_keystone_on_line(text, arch_key):
        return None

    keystone = _load_keystone_module()
    if keystone is not None:
        try:
            mode = keystone.KS_MODE_64 if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else keystone.KS_MODE_32
            ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
            encoded, _ = ks.asm(text, addr=ea, as_bytes=True)
            if encoded:
                return bytes(encoded)
        except Exception:
            pass

    mode_name = "64" if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else "32"
    helper = (
        "import sys\n"
        "from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64\n"
        "mode = KS_MODE_64 if sys.argv[1] == '64' else KS_MODE_32\n"
        "ks = Ks(KS_ARCH_X86, mode)\n"
        "enc, _ = ks.asm(sys.argv[3], addr=int(sys.argv[2], 0), as_bytes=True)\n"
        "print(bytes(enc).hex())\n"
    )
    for launcher in (["python"], ["py", "-3"]):
        if shutil.which(launcher[0]) is None:
            continue
        try:
            proc = subprocess.run(
                launcher + ["-c", helper, mode_name, hex(ea), text],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            continue

        if proc.returncode != 0:
            continue

        hex_text = (proc.stdout or "").strip()
        if not hex_text:
            continue
        try:
            return bytes.fromhex(hex_text)
        except ValueError:
            continue

    return None


def _assemble_bytes(ea, text, arch_key, original_entry=None):
    """Assemble one line after trying rewritten text and compatibility fallbacks."""
    prepared = _rewrite_line_for_assembly(text, arch_key, original_entry)
    prepared_note = None
    if prepared != text:
        prepared_note = "自动将栈变量表达式折算为真实偏移后汇编。"

    attempts = []
    seen = set()
    if prepared not in seen:
        attempts.append((prepared, prepared_note))
        seen.add(prepared)

    for candidate, note in _fallback_assembly_candidates(ea, prepared, arch_key, original_entry):
        candidate = _rewrite_line_for_assembly(candidate, arch_key, original_entry)
        if candidate in seen:
            continue
        merged_note = note
        if prepared_note:
            merged_note = (
                prepared_note
                if not note
                else "%s %s" % (prepared_note, note)
            )
        attempts.append((candidate, merged_note))
        seen.add(candidate)

    if text not in seen:
        attempts.append((text, None))
        seen.add(text)

    for candidate, note in attempts:
        buf = _try_assemble_line_keystone(ea, candidate, arch_key)
        if buf is not None:
            _debug_log(
                "assemble_line.success",
                assembler="keystone",
                ea="0x%X" % ea,
                original=text,
                assembled=candidate,
                note=note,
                bytes=buf,
            )
            if note:
                return buf, "%s 使用 Keystone 兼容汇编。" % note
            return buf, "使用 Keystone 兼容汇编。"

    for candidate, note in attempts:
        buf = _try_assemble_line(ea, candidate)
        if buf is not None:
            _debug_log(
                "assemble_line.success",
                assembler="ida",
                ea="0x%X" % ea,
                original=text,
                assembled=candidate,
                note=note,
                bytes=buf,
            )
            return buf, note

    buf, note = _assemble_direct_branch_bytes(ea, prepared, arch_key)
    if buf is not None:
        merged_note = note
        if prepared_note:
            merged_note = "%s %s" % (prepared_note, note)
        _debug_log(
            "assemble_line.success",
            assembler="manual_rel32",
            ea="0x%X" % ea,
            original=text,
            assembled=prepared,
            note=merged_note,
            bytes=buf,
        )
        return buf, merged_note

    _debug_log(
        "assemble_line.failure",
        ea="0x%X" % ea,
        original=text,
        attempts=" || ".join(candidate for candidate, _ in attempts),
    )
    raise RuntimeError("无法汇编: %s" % text)


def _assemble_multiline(ea, text, arch_key, original_entries=None):
    """Assemble multiple lines and preserve per-line preview metadata."""
    chunks = []
    notes = []
    line_infos = []
    current_ea = ea
    lines = [_sanitize_asm_line(line) for line in text.splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        raise RuntimeError("请输入至少一条汇编指令。")

    for index, line in enumerate(lines):
        original_entry = (
            original_entries[index]
            if original_entries is not None and index < len(original_entries)
            else None
        )
        chunk, note = _assemble_bytes(current_ea, line, arch_key, original_entry)
        chunks.append(chunk)
        if note:
            notes.append(note)
        line_infos.append({"line": line, "bytes": chunk, "note": note})
        current_ea += len(chunk)
    return b"".join(chunks), notes, line_infos


def _build_nop_bytes(ea, size):
    """Assemble enough NOP instructions to fill the requested byte count."""
    parts = []
    remaining = size
    current_ea = ea
    arch_key = _processor_key()

    while remaining > 0:
        nop_bytes, _ = _assemble_bytes(current_ea, "nop", arch_key)
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


def _patch_instruction(ea, patch_bytes):
    """Patch one instruction-sized region and recreate the instruction there."""
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(patch_bytes))
    ida_bytes.patch_bytes(ea, patch_bytes)
    ida_auto.auto_recreate_insn(ea)


def _patch_bytes_as_code(ea, patch_bytes):
    """Patch raw bytes and ask IDA to recreate code over the whole range."""
    end_ea = ea + len(patch_bytes)
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(patch_bytes))
    ida_bytes.patch_bytes(ea, patch_bytes)

    current = ea
    while current < end_ea:
        length = ida_auto.auto_recreate_insn(current)
        if length <= 0:
            current += 1
        else:
            current += length

    ida_kernwin.refresh_idaview_anyway()


def _apply_code_patch(ea, patch_bytes, write_to_file=False):
    """Patch bytes into IDA, and optionally sync the same bytes back to the input file."""
    file_path = ""
    if write_to_file:
        chunks = _build_file_patch_chunks(ea, patch_bytes)
        file_path = _write_patch_chunks_to_input_file(chunks)
        _debug_log(
            "input_file.write",
            ea="0x%X" % ea,
            byte_count=len(patch_bytes),
            file_path=file_path,
        )

    _patch_bytes_as_code(ea, patch_bytes)
    return file_path


def _attach_cave_to_owner_function(owner_ea, cave_start, cave_end):
    """Treat the cave as a tail chunk of the original function instead of a fake callee."""
    owner = ida_funcs.get_func(owner_ea)
    if owner is None:
        return False

    existing = ida_funcs.get_func(cave_start)
    if existing is not None and existing.start_ea == cave_start:
        ida_funcs.del_func(cave_start)

    if not ida_funcs.append_func_tail(owner, cave_start, cave_end):
        chunk = ida_funcs.get_fchunk(cave_start)
        if chunk is None or chunk.start_ea != cave_start or chunk.end_ea != cave_end:
            return False

    ida_funcs.reanalyze_function(owner)
    _debug_log(
        "trampoline.attach_tail",
        owner="0x%X" % owner.start_ea,
        cave_start="0x%X" % cave_start,
        cave_end="0x%X" % cave_end,
    )
    return True


def _hook_region(ctx, min_size=5):
    """Return a hook/trampoline region, auto-extending the current instruction if needed."""
    widget = getattr(ctx, "widget", None)
    has_selection, start_ea, end_ea = ida_kernwin.read_range_selection(widget)
    if has_selection and start_ea != ida_idaapi.BADADDR and end_ea > start_ea:
        size = end_ea - start_ea
        if size < min_size:
            raise RuntimeError("当前选中范围只有 %d bytes，至少需要 %d bytes 才能写入跳板。" % (size, min_size))
        return start_ea, size, "选中范围 0x%X - 0x%X" % (start_ea, end_ea), True

    start_ea = _current_ea(ctx)
    size = 0
    current = start_ea
    while size < min_size:
        item_size = ida_bytes.get_item_size(current)
        if item_size <= 0:
            item_size = 1
        size += item_size
        current += item_size
    return start_ea, size, "自动扩展当前地址 0x%X 起的 %d bytes" % (start_ea, size), False


def _max_segment_end():
    """Return the highest end address among all segments."""
    max_end = 0
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is not None and seg.end_ea > max_end:
            max_end = seg.end_ea
    return max_end


def _patch_segment_bitness():
    """Return IDA segment bitness code for the current database."""
    if idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT:
        return 2
    return 1


def _find_patch_segment():
    """Find the dedicated trampoline/code-cave segment if it already exists."""
    return ida_segment.get_segm_by_name(PATCH_SEGMENT_NAME)


def _next_patch_cursor(seg):
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
    return _align_up(cursor, PATCH_STUB_ALIGN)


def _ensure_patch_segment(required_size):
    """Create or extend the dedicated patch segment to fit a new trampoline stub."""
    seg = _find_patch_segment()
    if seg is None:
        start_ea = _align_up(_max_segment_end() + 0x1000, 0x1000)
        seg_size = _align_up(max(PATCH_SEGMENT_DEFAULT_SIZE, required_size + 0x100), 0x1000)
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
        ida_segment.set_segm_addressing(seg, _patch_segment_bitness())
        seg.perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_EXEC
        ida_segment.update_segm(seg)
        ida_segment.set_segment_cmt(
            seg,
            "ida_patch_pro trampoline segment. 默认只存在于 IDB，中转逻辑不自动扩展原始文件布局。",
            0,
        )
        _debug_log(
            "patch_segment.create",
            name=PATCH_SEGMENT_NAME,
            start="0x%X" % start_ea,
            size="0x%X" % seg_size,
        )
        return ida_segment.getseg(start_ea)

    cursor = _next_patch_cursor(seg)
    if seg.end_ea - cursor < required_size:
        new_end = _align_up(cursor + required_size + 0x100, 0x1000)
        if not ida_segment.set_segm_end(seg.start_ea, new_end, ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT):
            raise RuntimeError("无法扩展代码洞段 `%s` 到 0x%X。" % (PATCH_SEGMENT_NAME, new_end))
        seg = ida_segment.getseg(seg.start_ea)
        _debug_log(
            "patch_segment.extend",
            name=PATCH_SEGMENT_NAME,
            start="0x%X" % seg.start_ea,
            new_end="0x%X" % new_end,
            required_size="0x%X" % required_size,
        )
    return seg


def _trampoline_risk_notes(entries):
    """Return relocation warnings for overwritten instructions that may not be safe to replay."""
    notes = []
    for entry in entries:
        asm = (entry.get("asm") or "").lower()
        mnem = _extract_mnemonic(asm)
        if not mnem:
            continue
        if mnem.startswith("j") or mnem in ("call", "loop", "loope", "loopne", "ret", "syscall", "sysenter"):
            notes.append("0x%X: `%s` 是控制流相关指令，迁移到代码洞后应人工确认语义。" % (entry["ea"], entry["asm"]))
            continue
        if "[rip" in asm or "[eip" in asm:
            notes.append("0x%X: `%s` 包含 RIP/EIP 相对寻址，迁移后应人工确认地址是否仍正确。" % (entry["ea"], entry["asm"]))
    return notes


def _parse_stack_delta(line, arch_key):
    """Estimate the stack-pointer delta introduced by one custom instruction."""
    mnem, operands = _split_operands(line)
    if not mnem:
        return 0

    ptr_size = 8 if _pointer_bits() == 64 else 4
    mnem = mnem.lower()
    if mnem == "push":
        return -ptr_size
    if mnem == "pop":
        return ptr_size
    if mnem == "pushfq" or mnem == "pushfd":
        return -ptr_size
    if mnem == "popfq" or mnem == "popfd":
        return ptr_size
    if mnem in ("sub", "add") and len(operands) >= 2:
        dst = operands[0].strip().lower()
        value = _parse_immediate_value(operands[1])
        if value is None:
            return 0
        if dst in ("rsp", "esp"):
            return -value if mnem == "sub" else value
    return 0


def _x64_effective_pushpop_note(line):
    """Explain how IDA treats 32-bit push/pop spellings in x64 mode."""
    if _pointer_bits() != 64:
        return None
    mnem, operands = _split_operands(line)
    if mnem not in ("push", "pop") or not operands:
        return None
    reg = operands[0].strip().lower()
    base = _canonical_x64_reg(reg)
    if not base or reg == base:
        return None
    return "`%s %s` 在 x64 下实际按 `%s %s` 进行 64 位栈操作。" % (mnem, reg, mnem, base)


def _trampoline_custom_risk_notes(custom_lines):
    """Return warnings for custom trampoline code that may corrupt runtime state."""
    notes = []
    stack_delta = 0
    for line in custom_lines:
        note = _x64_effective_pushpop_note(line)
        if note:
            notes.append(note)
        stack_delta += _parse_stack_delta(line, _processor_key())

    if stack_delta != 0:
        direction = "减少" if stack_delta < 0 else "增加"
        notes.append(
            "自定义代码执行后 `rsp/esp` 净%s %d bytes；若没有在跳回前恢复，原函数栈平衡会被破坏。"
            % (direction, abs(stack_delta))
        )
    return notes


def _merge_operand_infos(entries):
    """Merge operand rewrite metadata from multiple instructions into one reusable context."""
    merged = []
    seen = set()
    for entry in entries or []:
        for info in entry.get("operand_infos") or []:
            normalized = info.get("normalized")
            asm_operand = info.get("asm_operand")
            if not normalized or not asm_operand:
                continue
            key = (normalized, asm_operand, info.get("size_keyword"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(
                {
                    "index": info.get("index", 0),
                    "display": info.get("display", ""),
                    "normalized": normalized,
                    "asm_operand": asm_operand,
                    "normalized_asm": info.get("normalized_asm", _normalize_mem_operand(asm_operand)),
                    "size_keyword": info.get("size_keyword"),
                }
            )
    return merged


def _parse_trampoline_orig_marker(line):
    """Parse `{{orig}}` / `{{orig:N}}` placeholders used in trampoline custom code."""
    match = TRAMPOLINE_ORIG_MARKER_RE.match(line.strip())
    if not match:
        return None
    token = (match.group(1) or "all").strip().lower()
    if token == "all":
        return "all"
    index = int(token, 10) - 1
    if index < 0:
        raise RuntimeError("原指令占位符下标从 1 开始，例如 `{{orig:1}}`。")
    return index


def _append_trampoline_original_line(lines, line_entries, replayed_entries, entry, source_tag):
    """Append one replayed original instruction into the trampoline body."""
    asm = entry.get("asm") or ""
    if not asm:
        raise RuntimeError("原始指令缺少可回放的汇编文本。")
    lines.append(asm)
    line_entries.append(entry)
    replayed_entries.append(entry)
    _debug_log(
        "trampoline.original_insert",
        source=source_tag,
        ea="0x%X" % entry.get("ea", 0),
        asm=asm,
    )


def _build_trampoline_lines(custom_text, original_entries, return_ea, include_original):
    """Build the final cave assembly lines and mapping to original entries."""
    custom_lines = [_sanitize_asm_line(line) for line in custom_text.splitlines()]
    custom_lines = [line for line in custom_lines if line]
    custom_context = None
    custom_operand_infos = _merge_operand_infos(original_entries)
    if custom_operand_infos:
        custom_context = {
            "asm": "",
            "operand_infos": custom_operand_infos,
        }

    lines = []
    line_entries = []
    replayed_entries = []
    consumed_indices = set()

    for line in custom_lines:
        marker = _parse_trampoline_orig_marker(line)
        if marker is None:
            lines.append(line)
            line_entries.append(custom_context)
            continue

        if marker == "all":
            inserted = 0
            for index, entry in enumerate(original_entries):
                if index in consumed_indices:
                    continue
                _append_trampoline_original_line(lines, line_entries, replayed_entries, entry, "{{orig}}")
                consumed_indices.add(index)
                inserted += 1
            if inserted == 0:
                raise RuntimeError("`{{orig}}` 没有可插入的剩余原始指令。")
            continue

        if marker >= len(original_entries):
            raise RuntimeError(
                "原指令占位符 `{{orig:%d}}` 超出范围，当前只覆盖了 %d 条原始指令。"
                % (marker + 1, len(original_entries))
            )
        _append_trampoline_original_line(
            lines,
            line_entries,
            replayed_entries,
            original_entries[marker],
            "{{orig:%d}}" % (marker + 1),
        )
        consumed_indices.add(marker)

    if include_original:
        for index, entry in enumerate(original_entries):
            if index in consumed_indices:
                continue
            _append_trampoline_original_line(lines, line_entries, replayed_entries, entry, "auto-append")
            consumed_indices.add(index)

    lines.append("jmp 0x%X" % return_ea)
    line_entries.append(None)
    return lines, line_entries, [original_entries[index] for index in sorted(consumed_indices)]


def _find_file_trampoline_site(start_ea, cave_text, cave_entries):
    """Find a file-backed cave and assemble the trampoline stub there."""
    arch_key = _processor_key()
    probe_ea = start_ea
    site = None
    for _ in range(6):
        cave_bytes, _, cave_infos = _assemble_multiline(probe_ea, cave_text, arch_key, cave_entries)
        site = _find_file_code_cave(len(cave_bytes), preferred_ea=start_ea)
        if probe_ea == site["start"] and len(cave_bytes) <= site["available_size"]:
            return site["segment"], site["start"], cave_bytes, cave_infos
        probe_ea = site["start"]

    cave_bytes, _, cave_infos = _assemble_multiline(probe_ea, cave_text, arch_key, cave_entries)
    if site is None or len(cave_bytes) > site["available_size"]:
        site = _find_file_code_cave(len(cave_bytes), preferred_ea=start_ea)
        probe_ea = site["start"]
        cave_bytes, _, cave_infos = _assemble_multiline(probe_ea, cave_text, arch_key, cave_entries)
    return site["segment"], probe_ea, cave_bytes, cave_infos


def _preview_trampoline_plan(start_ea, region_size, custom_text, original_entries, include_original, write_to_file=False):
    """Preview trampoline bytes without mutating the database."""
    return_ea = start_ea + region_size
    lines, line_entries, replayed_entries = _build_trampoline_lines(
        custom_text,
        original_entries,
        return_ea,
        include_original,
    )
    if not lines:
        raise RuntimeError("代码洞内容为空。至少要保留原始指令或填写自定义汇编。")

    custom_lines = [_sanitize_asm_line(line) for line in custom_text.splitlines()]
    custom_lines = [line for line in custom_lines if line]
    cave_entries = list(line_entries)
    cave_text = "\n".join(lines)

    if write_to_file:
        file_plan = _prepare_file_patch_segment(PATCH_STUB_ALIGN, apply_changes=False)
        seg = file_plan.get("segment")
        cave_start = _next_patch_cursor(seg) if seg is not None else file_plan["ea_start"]
        for _ in range(6):
            cave_bytes, _, cave_infos = _assemble_multiline(cave_start, cave_text, _processor_key(), cave_entries)
            required_total = (cave_start - file_plan["ea_start"]) + len(cave_bytes) + PATCH_STUB_ALIGN
            if required_total <= file_plan["raw_size"]:
                break
            file_plan = _prepare_file_patch_segment(required_total, apply_changes=False)
            seg = file_plan.get("segment")
            cave_start = _next_patch_cursor(seg) if seg is not None else file_plan["ea_start"]
        storage_mode = "file_section"
        segment_name = file_plan["section_name"]
        alloc_base_ea = file_plan["ea_start"]
    else:
        seg = _ensure_patch_segment(0x200)
        cave_start = _next_patch_cursor(seg)
        cave_bytes, _, cave_infos = _assemble_multiline(cave_start, cave_text, _processor_key(), cave_entries)
        storage_mode = "idb"
        segment_name = PATCH_SEGMENT_NAME
        alloc_base_ea = cave_start
    entry_bytes, _ = _assemble_bytes(start_ea, "jmp 0x%X" % cave_start, _processor_key())

    if len(entry_bytes) > region_size:
        raise RuntimeError("入口跳板需要 %d bytes，但当前覆盖范围只有 %d bytes。" % (len(entry_bytes), region_size))

    _debug_log(
        "trampoline.preview_plan",
        start_ea="0x%X" % start_ea,
        region_size=region_size,
        cave_start="0x%X" % cave_start,
        cave_size=len(cave_bytes),
        include_original=include_original,
        storage_mode=storage_mode,
        write_to_file=write_to_file,
        segment_name=segment_name,
        custom_text=custom_text,
        line_count=len(lines),
    )
    return {
        "segment": seg,
        "segment_name": segment_name,
        "cave_start": cave_start,
        "cave_end": cave_start + len(cave_bytes),
        "entry_bytes": entry_bytes,
        "cave_bytes": cave_bytes,
        "cave_infos": cave_infos,
        "return_ea": return_ea,
        "risk_notes": (
            _trampoline_custom_risk_notes(custom_lines)
            + (["当前代码洞仅存在于 IDB；未写入输入文件时，运行程序或启动调试将跳转到不存在的地址。"] if not write_to_file else [])
            + _trampoline_risk_notes(replayed_entries)
        ),
        "lines": lines,
        "include_original": include_original,
        "write_to_file": write_to_file,
        "storage_mode": storage_mode,
        "replayed_entries": replayed_entries,
        "alloc_base_ea": alloc_base_ea,
    }


def _load_qt():
    """Import PySide6 lazily so the module loads cleanly inside IDA."""
    from PySide6 import QtCore, QtGui, QtWidgets

    return QtCore, QtGui, QtWidgets


def _show_modeless_dialog(owner):
    """Show a dialog modelessly and keep the wrapper object alive until close."""
    QtCore, _, _ = _load_qt()
    dialog = owner.dialog
    dialog.setModal(False)
    dialog.setWindowModality(QtCore.Qt.NonModal)
    dialog.setAttribute(QtCore.Qt.WA_DeleteOnClose, True)

    if owner not in _MODELLESS_DIALOGS:
        _MODELLESS_DIALOGS.append(owner)

    def cleanup(*_args):
        try:
            _MODELLESS_DIALOGS.remove(owner)
        except ValueError:
            pass

    try:
        dialog.finished.connect(cleanup)
    except Exception:
        pass
    try:
        dialog.destroyed.connect(cleanup)
    except Exception:
        pass

    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
    return 1


class ReferenceTableDialog:
    """Shared searchable table dialog used by syntax and register references."""

    def __init__(self, title, note_text, headers, rows, monospace_columns=None, parent=None):
        """Build a generic filterable reference table."""
        QtCore, QtGui, QtWidgets = _load_qt()
        monospace_columns = set(monospace_columns or [])

        self.dialog = QtWidgets.QDialog(parent)
        self.dialog.setWindowTitle(title)
        self.dialog.resize(1080, 520)
        self._rows = list(rows)
        self._QtWidgets = QtWidgets
        self._QtGui = QtGui

        layout = QtWidgets.QVBoxLayout(self.dialog)

        note = QtWidgets.QLabel(note_text, self.dialog)
        note.setWordWrap(True)
        layout.addWidget(note)

        self.search_edit = QtWidgets.QLineEdit(self.dialog)
        self.search_edit.setPlaceholderText("输入关键字过滤，例如 mov / rsp / xmm0 / return / 参数")
        self.search_edit.textChanged.connect(self._apply_filter)
        layout.addWidget(self.search_edit)

        self.table = QtWidgets.QTableWidget(self.dialog)
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setRowCount(len(self._rows))
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)

        monospace_font = QtGui.QFont("Consolas")
        for row_index, row in enumerate(self._rows):
            for col_index, value in enumerate(row):
                item = QtWidgets.QTableWidgetItem(value)
                if col_index in monospace_columns:
                    item.setFont(monospace_font)
                self.table.setItem(row_index, col_index, item)

        header = self.table.horizontalHeader()
        for col_index in range(max(0, len(headers) - 1)):
            header.setSectionResizeMode(col_index, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(len(headers) - 1, QtWidgets.QHeaderView.Stretch)
        layout.addWidget(self.table)

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close, parent=self.dialog)
        buttons.rejected.connect(self.dialog.reject)
        buttons.accepted.connect(self.dialog.accept)
        layout.addWidget(buttons)

    def _apply_filter(self, text):
        """Hide rows that do not match the current search keyword."""
        needle = (text or "").strip().lower()
        for row_index, row in enumerate(self._rows):
            haystack = " ".join(row).lower()
            self.table.setRowHidden(row_index, bool(needle) and needle not in haystack)

    def exec(self):
        """Show the reference dialog modally."""
        return self.dialog.exec()


class SyntaxHelpDialog:
    """Architecture-specific syntax quick reference dialog."""

    def __init__(self, category, parent=None):
        """Build the quick reference table for the selected architecture."""
        info = ARCH_SYNTAX_HELP[category]
        self.reference = ReferenceTableDialog(
            "汇编语法帮助 - %s" % category,
            info["note"],
            ["示例", "语法", "典型十六进制", "典型字节长度", "含义"],
            info["rows"],
            monospace_columns=(0, 1, 2),
            parent=parent,
        )

    def exec(self):
        """Show the syntax help dialog modally."""
        return self.reference.exec()


class RegisterHelpDialog:
    """Architecture-specific register quick reference dialog."""

    def __init__(self, category, parent=None):
        """Build the register reference table for the selected architecture."""
        info = ARCH_REGISTER_HELP[category]
        self.reference = ReferenceTableDialog(
            "寄存器速查表 - %s" % category,
            info["note"],
            ["寄存器", "类别", "常见用途", "补充说明"],
            info["rows"],
            monospace_columns=(0,),
            parent=parent,
        )

    def exec(self):
        """Show the register help dialog modally."""
        return self.reference.exec()


class ShortcutSettingsDialog:
    """Edit and persist plugin action shortcuts."""

    def __init__(self, parent=None):
        """Build the shortcut settings dialog."""
        _, QtGui, QtWidgets = _load_qt()
        self._QtWidgets = QtWidgets
        self.dialog = QtWidgets.QDialog(parent)
        self.dialog.setWindowTitle("快捷键设置")
        self.dialog.resize(640, 320)
        self._edits = {}
        self._defaults = _default_action_shortcuts()

        root = QtWidgets.QVBoxLayout(self.dialog)

        note = QtWidgets.QLabel(
            "修改后会保存到本地设置文件，并尽量立即更新到当前 IDA 会话。"
            " 留空表示不为该动作设置快捷键。",
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        form = QtWidgets.QFormLayout()
        current = _load_action_shortcuts()
        for action_name, label, default_shortcut in ACTION_SHORTCUT_SPECS:
            edit = QtWidgets.QLineEdit(self.dialog)
            edit.setPlaceholderText(default_shortcut or "例如: Ctrl+Alt+A")
            edit.setText(current.get(action_name) or "")
            form.addRow("%s:" % label, edit)
            self._edits[action_name] = edit
        root.addLayout(form)

        self.status = QtWidgets.QLabel("", self.dialog)
        root.addWidget(self.status)

        toolbar = QtWidgets.QHBoxLayout()
        self.reset_btn = QtWidgets.QPushButton("恢复默认", self.dialog)
        self.reset_btn.clicked.connect(self._reset_defaults)
        toolbar.addWidget(self.reset_btn)

        toolbar.addStretch(1)

        self.save_btn = QtWidgets.QPushButton("保存", self.dialog)
        self.save_btn.clicked.connect(self._save)
        toolbar.addWidget(self.save_btn)

        self.close_btn = QtWidgets.QPushButton("关闭", self.dialog)
        self.close_btn.clicked.connect(self.dialog.close)
        toolbar.addWidget(self.close_btn)
        root.addLayout(toolbar)

    def _collect_shortcuts(self):
        """Collect normalized shortcut strings from the line edits."""
        return {
            action_name: _normalize_shortcut_text(edit.text())
            for action_name, edit in self._edits.items()
        }

    def _reset_defaults(self):
        """Reset all editable shortcuts to the built-in defaults."""
        for action_name, edit in self._edits.items():
            edit.setText(self._defaults.get(action_name) or "")
        self.status.setText("已恢复默认快捷键，点击“保存”后生效。")

    def _save(self):
        """Save current shortcuts and apply them to the running session when possible."""
        shortcuts = self._collect_shortcuts()
        _save_action_shortcuts(shortcuts)
        applied = _apply_registered_shortcuts(shortcuts)
        if applied:
            self.status.setText("快捷键已保存，并已立即应用到当前 IDA 会话。")
        else:
            self.status.setText("快捷键已保存。若当前会话未立即更新，重载插件后生效。")
        ida_kernwin.msg("[%s] 快捷键设置已保存。\n" % PLUGIN_NAME)

    def exec(self):
        """Show the shortcut settings dialog modelessly."""
        return _show_modeless_dialog(self)


class RollbackHistoryDialog:
    """List recorded patch transactions and let the user rollback any selected one."""

    def __init__(self, ctx):
        """Build the rollback history list dialog."""
        _, QtGui, QtWidgets = _load_qt()
        self._QtGui = QtGui
        self._QtWidgets = QtWidgets
        self.ctx = ctx
        self.current_ea = _history_target_ea(ctx)
        self._rows = []

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("补丁回撤列表")
        self.dialog.resize(1080, 540)

        root = QtWidgets.QVBoxLayout(self.dialog)

        note = QtWidgets.QLabel(
            "这里会列出插件记录过的补丁事务。你可以手动选择要回撤的那一次。"
            " 如果多次修改同一地址，回撤旧事务会直接恢复当时的旧字节，可能覆盖后来的补丁。",
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        current = QtWidgets.QLabel("当前定位地址: 0x%X" % self.current_ea, self.dialog)
        root.addWidget(current)

        body = QtWidgets.QHBoxLayout()

        self.table = QtWidgets.QTableWidget(self.dialog)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["状态", "类型", "目标", "代码洞", "写回文件", "时间"])
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._refresh_details)
        self.table.cellDoubleClicked.connect(lambda *_args: self._rollback_selected())
        body.addWidget(self.table, 3)

        self.detail = QtWidgets.QPlainTextEdit(self.dialog)
        self.detail.setReadOnly(True)
        self.detail.setFont(QtGui.QFont("Consolas"))
        body.addWidget(self.detail, 2)

        root.addLayout(body)

        toolbar = QtWidgets.QHBoxLayout()
        self.status = QtWidgets.QLabel("", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.refresh_btn = QtWidgets.QPushButton("刷新列表", self.dialog)
        self.refresh_btn.clicked.connect(self._reload_entries)
        toolbar.addWidget(self.refresh_btn)

        self.rollback_btn = QtWidgets.QPushButton("回撤所选", self.dialog)
        self.rollback_btn.clicked.connect(self._rollback_selected)
        toolbar.addWidget(self.rollback_btn)

        self.close_btn = QtWidgets.QPushButton("关闭", self.dialog)
        self.close_btn.clicked.connect(self.dialog.close)
        toolbar.addWidget(self.close_btn)
        root.addLayout(toolbar)

        self._reload_entries()

    def _build_rows(self):
        """Collect display rows from persisted history."""
        rows = []
        for entry in reversed(_load_patch_history()):
            meta = entry.get("meta") or {}
            stored_imagebase = _transaction_imagebase(meta)
            target_ea = _rebase_history_ea(entry.get("target_ea", 0), stored_imagebase)
            cave_start = _rebase_history_ea(meta.get("cave_start"), stored_imagebase)
            runtime_status = _entry_runtime_status(entry)
            rows.append(
                {
                    "entry": entry,
                    "runtime_status": runtime_status,
                    "can_rollback": _entry_can_rollback(entry),
                    "target_ea": target_ea,
                    "cave_start": cave_start,
                    "write_to_file": bool(meta.get("write_to_file")),
                    "hits_current_ea": _history_entry_matches_ea(entry, self.current_ea),
                }
            )
        return rows

    def _selected_row(self):
        """Return the currently selected history row, or None."""
        row = self.table.currentRow()
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]

    def _select_preferred_row(self):
        """Pick a sensible default selection after reloading the list."""
        if not self._rows:
            return
        for index, row in enumerate(self._rows):
            if row["hits_current_ea"] and row["can_rollback"]:
                self.table.selectRow(index)
                return
        for index, row in enumerate(self._rows):
            if row["can_rollback"]:
                self.table.selectRow(index)
                return
        self.table.selectRow(0)

    def _reload_entries(self):
        """Reload history from disk and refresh the table/detail panel."""
        QtGui = self._QtGui
        QtWidgets = self._QtWidgets
        self._rows = self._build_rows()
        self.table.setRowCount(len(self._rows))

        font = QtGui.QFont("Consolas")
        for row_index, row in enumerate(self._rows):
            entry = row["entry"]
            created_at = entry.get("created_at")
            values = [
                _entry_runtime_status_text(row["runtime_status"]),
                entry.get("label") or entry.get("kind") or "",
                "0x%X" % (row["target_ea"] or 0),
                ("0x%X" % row["cave_start"]) if row["cave_start"] is not None else "",
                "是" if row["write_to_file"] else "否",
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_at)) if created_at else "",
            ]
            for col_index, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                if col_index in (2, 3):
                    item.setFont(font)
                self.table.setItem(row_index, col_index, item)

        header = self.table.horizontalHeader()
        for col_index in range(5):
            header.setSectionResizeMode(col_index, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QtWidgets.QHeaderView.Stretch)

        if self._rows:
            self.status.setText("共 %d 条补丁事务记录。" % len(self._rows))
            self._select_preferred_row()
        else:
            self.status.setText("当前还没有插件补丁记录。")
            self.detail.setPlainText("")
            self.rollback_btn.setEnabled(False)

        self._refresh_details()

    def _refresh_details(self):
        """Refresh the right-side detail panel for the selected row."""
        row = self._selected_row()
        if row is None:
            self.detail.setPlainText("")
            self.rollback_btn.setEnabled(False)
            return

        lines = [
            "状态: %s" % _entry_runtime_status_text(row["runtime_status"]),
            _describe_history_entry(row["entry"]),
        ]
        if row["hits_current_ea"]:
            lines.append("命中当前地址: 是")
        else:
            lines.append("命中当前地址: 否")
        if row["runtime_status"] == "stale":
            lines.append("说明: 历史记录已标成回撤，但当前 IDB 里仍有残留补丁字节。")
        elif not row["can_rollback"]:
            lines.append("说明: 这条记录已经回撤完成，目前仅供查看。")

        self.detail.setPlainText("\n\n".join(lines))
        self.rollback_btn.setEnabled(row["can_rollback"])

    def _rollback_selected(self):
        """Rollback the currently selected history transaction."""
        row = self._selected_row()
        if row is None:
            return
        if not row["can_rollback"]:
            ida_kernwin.warning("当前所选事务已经回撤完成，不能再次回撤。")
            return

        prompt = "即将回撤所选补丁事务："
        if row["runtime_status"] == "stale":
            prompt = "检测到这条事务存在 IDB 残留，将执行一次修复性回撤："
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "%s\n\n%s\n\n是否继续？" % (prompt, _describe_history_entry(row["entry"])),
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return

        _rollback_transaction(row["entry"])
        ida_kernwin.msg(
            "[%s] 已回撤补丁事务: %s @ 0x%X。\n"
            % (
                PLUGIN_NAME,
                row["entry"].get("label") or row["entry"].get("kind"),
                row["target_ea"] or 0,
            )
        )
        self._reload_entries()

    def exec(self):
        """Show the rollback dialog modelessly so IDA stays interactive."""
        return _show_modeless_dialog(self)


class AssemblePatchDialog:
    """Main assemble/preview/apply dialog opened from the popup menu."""

    def __init__(self, ctx):
        """Initialize dialog state from the current disassembly selection."""
        QtCore, QtGui, QtWidgets = _load_qt()
        self.QtWidgets = QtWidgets
        self.ctx = ctx
        self.arch_key = _processor_key()
        (
            self.start_ea,
            self.region_size,
            self.region_desc,
            self.has_selection,
        ) = _patch_region(ctx)
        self.trace_id = _make_trace_id("asm", self.start_ea)

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("Assemble")
        self.dialog.resize(1080, 460)

        # 原始上下文：用于回显、长度比较、栈变量折算和模板建议。
        self.original_entries = _get_original_entries(ctx)
        self.original_text = "\n".join(entry["text"] for entry in self.original_entries if entry["text"])
        self.original_asm_text = _join_entry_asm_lines(self.original_entries)
        self.original_bytes = b"".join(entry["bytes"] for entry in self.original_entries)

        # 当前预览状态：仅在最近一次预览成功时与编辑框内容同步。
        self.preview_text = self.original_asm_text
        self.preview_bytes = self.original_bytes
        self.preview_infos = _build_preview_infos_from_entries(self.original_entries)

        root = QtWidgets.QVBoxLayout(self.dialog)

        target = QtWidgets.QLabel(
            "目标: %s | 可覆盖大小: %d bytes" % (self.region_desc, self.region_size),
            self.dialog,
        )
        root.addWidget(target)

        note = QtWidgets.QLabel(
            "说明: 输入一条或多条汇编。若结果小于目标范围，剩余字节会自动填充为 NOP。",
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        body = QtWidgets.QHBoxLayout()

        self.editor = QtWidgets.QPlainTextEdit(self.dialog)
        self.editor.setPlaceholderText("例如:\nmov eax, 1\nxor ecx, ecx")
        font = QtGui.QFont("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)
        self.editor.setFont(font)
        body.addWidget(self.editor, 3)

        self.hint_panel = QtWidgets.QPlainTextEdit(self.dialog)
        self.hint_panel.setReadOnly(True)
        self.hint_panel.setFont(font)
        body.addWidget(self.hint_panel, 2)
        root.addLayout(body)

        toolbar = QtWidgets.QHBoxLayout()
        self.status = QtWidgets.QLabel("当前未输入汇编。", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.preview_btn = QtWidgets.QPushButton("预览机器码", self.dialog)
        self.preview_btn.clicked.connect(self._preview_machine_code)
        toolbar.addWidget(self.preview_btn)

        self.syntax_btn = QtWidgets.QToolButton(self.dialog)
        self.syntax_btn.setText("语法")
        self.syntax_btn.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        self.syntax_btn.setMenu(self._build_syntax_menu())
        toolbar.addWidget(self.syntax_btn)

        self.register_btn = QtWidgets.QToolButton(self.dialog)
        self.register_btn.setText("寄存器")
        self.register_btn.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        self.register_btn.setMenu(self._build_register_menu())
        toolbar.addWidget(self.register_btn)

        self.write_to_file = QtWidgets.QCheckBox("同时写入输入文件", self.dialog)
        self.write_to_file.setToolTip("勾选后会把补丁同步写回当前 IDB 对应的原始输入文件。")
        toolbar.addWidget(self.write_to_file)
        root.addLayout(toolbar)

        buttons = QtWidgets.QDialogButtonBox(self.dialog)
        self.apply_btn = buttons.addButton("应用", QtWidgets.QDialogButtonBox.AcceptRole)
        self.cancel_btn = buttons.addButton("取消", QtWidgets.QDialogButtonBox.RejectRole)
        self.apply_btn.clicked.connect(self._apply_patch)
        self.cancel_btn.clicked.connect(self.dialog.reject)
        root.addWidget(buttons)
        self.editor.setPlainText(self.original_asm_text)
        self.status.setText("已载入当前指令。点击“预览机器码”或直接“应用”。")
        self.editor.textChanged.connect(self._on_text_changed)
        self._refresh_context_panel()
        _debug_log(
            "assemble_dialog.open",
            trace_id=self.trace_id,
            start_ea="0x%X" % self.start_ea,
            region_size=self.region_size,
            original_asm=self.original_asm_text,
            input_file=_input_file_path(),
        )

    def _build_syntax_menu(self):
        """Create the quick reference dropdown menu."""
        _, _, QtWidgets = _load_qt()
        menu = QtWidgets.QMenu(self.dialog)

        current_key = _processor_key()
        current_action = menu.addAction("当前架构: %s" % current_key)
        current_action.triggered.connect(
            lambda checked=False, cat=current_key: self._show_syntax_help(cat)
        )

        menu.addSeparator()
        for category in ("x86/x64", "ARM/Thumb", "AArch64", "MIPS"):
            action = menu.addAction(category)
            action.triggered.connect(lambda checked=False, cat=category: self._show_syntax_help(cat))
        return menu

    def _show_syntax_help(self, category):
        """Open the syntax help dialog for the selected architecture."""
        SyntaxHelpDialog(category, self.dialog).exec()

    def _build_register_menu(self):
        """Create the register reference dropdown menu."""
        _, _, QtWidgets = _load_qt()
        menu = QtWidgets.QMenu(self.dialog)

        current_key = _processor_key()
        current_action = menu.addAction("当前架构: %s" % current_key)
        current_action.triggered.connect(
            lambda checked=False, cat=current_key: self._show_register_help(cat)
        )

        menu.addSeparator()
        for category in ("x86/x64", "ARM/Thumb", "AArch64", "MIPS"):
            action = menu.addAction(category)
            action.triggered.connect(lambda checked=False, cat=category: self._show_register_help(cat))
        return menu

    def _show_register_help(self, category):
        """Open the register help dialog for the selected architecture."""
        RegisterHelpDialog(category, self.dialog).exec()

    def _on_text_changed(self):
        """Reset preview state when editor content changes."""
        current_text = self.editor.toPlainText().strip()
        if current_text == self.original_asm_text:
            self.preview_text = self.original_asm_text
            self.preview_bytes = self.original_bytes
            self.preview_infos = _build_preview_infos_from_entries(self.original_entries)
        elif current_text != self.preview_text:
            self.preview_bytes = None
            self.preview_infos = None
        if current_text:
            self.status.setText("编辑中。点击“预览机器码”或直接“应用”。")
        else:
            self.status.setText("当前未输入汇编。")
        self._refresh_context_panel()

    def _preview_machine_code(self):
        """Assemble current editor text and refresh preview/status output."""
        text = self.editor.toPlainText().strip()
        if not text:
            self.status.setText("当前未输入汇编。")
            self.preview_text = ""
            self.preview_bytes = None
            self.preview_infos = None
            self._refresh_context_panel()
            return

        try:
            _debug_log(
                "assemble_dialog.preview.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                text=text,
            )
            self.preview_bytes, notes, self.preview_infos = _assemble_multiline(
                self.start_ea, text, self.arch_key, self.original_entries
            )
            self.preview_text = text
            self.status.setText(
                "预览成功: %d bytes / 当前范围: %d bytes"
                % (len(self.preview_bytes), self.region_size)
            )
            _debug_log(
                "assemble_dialog.preview.success",
                trace_id=self.trace_id,
                byte_count=len(self.preview_bytes),
                notes=" | ".join(notes),
            )
        except Exception as exc:
            self.preview_text = ""
            self.preview_bytes = None
            self.preview_infos = None
            self.status.setText("预览失败: %s" % exc)
            _debug_log_exception(
                "assemble_dialog.preview.failure",
                exc,
                trace_id=self.trace_id,
                text=text,
            )
        self._refresh_context_panel()

    def _refresh_context_panel(self):
        """Refresh the right-side hint panel from current editor/preview state."""
        text = self.editor.toPlainText().strip()
        preview_bytes = self.preview_bytes if text and text == self.preview_text else None
        preview_infos = self.preview_infos if text and text == self.preview_text else None

        self.hint_panel.setPlainText(
            _build_hint_text(
                self.original_entries,
                text,
                preview_bytes,
                preview_infos,
                self.region_size,
                self.has_selection,
                self.start_ea,
                self.arch_key,
            )
        )

    def _apply_patch(self):
        """Assemble current text and write the resulting bytes into IDA."""
        text = self.editor.toPlainText().strip()
        transaction = None
        applied_count = 0
        try:
            _debug_log(
                "assemble_dialog.apply.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                text=text,
                write_to_file=self.write_to_file.isChecked(),
            )
            patch_bytes, _, line_infos = _assemble_multiline(
                self.start_ea, text, self.arch_key, self.original_entries
            )
            if len(patch_bytes) > self.region_size:
                if self.has_selection:
                    raise RuntimeError(
                        "汇编结果为 %d bytes，已超过当前选中范围的 %d bytes。"
                        % (len(patch_bytes), self.region_size)
                    )

                answer = ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_NO,
                    "汇编结果为 %d bytes，已超过当前指令的 %d bytes。\n\n"
                    "是否继续覆盖后续字节？"
                    % (len(patch_bytes), self.region_size),
                )
                if answer != ida_kernwin.ASKBTN_YES:
                    return
                self.region_size = len(patch_bytes)

            if len(patch_bytes) < self.region_size:
                patch_bytes += _build_nop_bytes(
                    self.start_ea + len(patch_bytes),
                    self.region_size - len(patch_bytes),
                )

            transaction = _begin_patch_transaction(
                "assemble",
                "修改汇编",
                self.start_ea,
                trace_id=self.trace_id,
                meta={
                    "region_size": self.region_size,
                    "write_to_file": self.write_to_file.isChecked(),
                },
            )
            _record_transaction_operation(
                transaction,
                self.start_ea,
                patch_bytes,
                write_to_file=self.write_to_file.isChecked(),
                note="assemble_patch",
            )

            file_path = _apply_code_patch(
                self.start_ea,
                patch_bytes,
                write_to_file=self.write_to_file.isChecked(),
            )
            applied_count = 1
            _commit_patch_transaction(transaction)
            self.preview_text = text
            self.preview_bytes = patch_bytes
            self.preview_infos = line_infos
            if self.write_to_file.isChecked():
                ida_kernwin.msg(
                    "[%s] 已写入 %d bytes 到 0x%X，并同步到输入文件: %s。\n"
                    % (PLUGIN_NAME, len(patch_bytes), self.start_ea, file_path)
                )
            else:
                ida_kernwin.msg(
                    "[%s] 已写入 %d bytes 到 0x%X。\n"
                    % (PLUGIN_NAME, len(patch_bytes), self.start_ea)
                )
            _debug_log(
                "assemble_dialog.apply.success",
                trace_id=self.trace_id,
                byte_count=len(patch_bytes),
                start_ea="0x%X" % self.start_ea,
                write_to_file=self.write_to_file.isChecked(),
                file_path=file_path,
            )
            self.dialog.accept()
        except Exception as exc:
            try:
                _rollback_partial_transaction(transaction, applied_count)
            except Exception as rollback_exc:
                _debug_log_exception(
                    "assemble_dialog.partial_rollback.failure",
                    rollback_exc,
                    trace_id=self.trace_id,
                )
            _debug_log_exception(
                "assemble_dialog.apply.failure",
                exc,
                trace_id=self.trace_id,
                text=text,
            )
            ida_kernwin.warning("修改汇编失败:\n%s" % exc)

    def exec(self):
        """Show the assemble dialog modelessly so IDA stays interactive."""
        return _show_modeless_dialog(self)


class TrampolinePatchDialog:
    """Trampoline/code-cave dialog for CE-style jump patching."""

    def __init__(self, ctx):
        """Initialize the trampoline dialog from the current disassembly context."""
        QtCore, QtGui, QtWidgets = _load_qt()
        self.ctx = ctx
        self.arch_key = _processor_key()
        if self.arch_key != "x86/x64":
            raise RuntimeError("当前版本的代码注入仅支持 x86/x64。")

        (
            self.start_ea,
            self.region_size,
            self.region_desc,
            self.has_selection,
        ) = _hook_region(ctx, 5)
        self.trace_id = _make_trace_id("tramp", self.start_ea)

        self.original_entries = _get_entries_for_range(self.start_ea, self.region_size)
        self.original_asm_text = _join_entry_asm_lines(self.original_entries)
        self.preview_plan = None
        self.preview_text = ""

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("代码注入 / Trampoline")
        self.dialog.resize(1120, 540)

        root = QtWidgets.QVBoxLayout(self.dialog)

        target = QtWidgets.QLabel(
            "目标: %s | 覆盖大小: %d bytes" % (self.region_desc, self.region_size),
            self.dialog,
        )
        root.addWidget(target)

        note = QtWidgets.QLabel(
            "说明: 原地址会写入 `jmp` 跳板，再在代码洞里执行你的自定义代码。"
            " 不勾选“同时写入输入文件”时，代码洞只存在于 IDB 的 `%s` 段；"
            " 勾选后会自动创建/扩展输入文件中的 `%s` 节，适合实际运行和调试。"
            % (PATCH_SEGMENT_NAME, PATCH_FILE_SECTION_NAME),
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        body = QtWidgets.QHBoxLayout()

        self.editor = QtWidgets.QPlainTextEdit(self.dialog)
        self.editor.setPlaceholderText(
            "例如:\n; 编辑代码洞主体。末尾回跳会自动追加。\ncall func1\nmov eax, 1234h\ncall func2"
        )
        font = QtGui.QFont("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)
        self.editor.setFont(font)
        body.addWidget(self.editor, 3)

        self.hint_panel = QtWidgets.QPlainTextEdit(self.dialog)
        self.hint_panel.setReadOnly(True)
        self.hint_panel.setFont(font)
        body.addWidget(self.hint_panel, 2)
        root.addLayout(body)

        toolbar = QtWidgets.QHBoxLayout()
        self.status = QtWidgets.QLabel("当前未预览代码洞。", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.include_original = QtWidgets.QCheckBox("末尾自动补齐未保留的原指令并跳回", self.dialog)
        self.include_original.setChecked(False)
        self.include_original.stateChanged.connect(self._on_text_changed)
        toolbar.addWidget(self.include_original)

        self.load_original_btn = QtWidgets.QPushButton("载入原指令", self.dialog)
        self.load_original_btn.clicked.connect(self._load_original_into_editor)
        toolbar.addWidget(self.load_original_btn)

        self.write_to_file = QtWidgets.QCheckBox("同时写入输入文件", self.dialog)
        self.write_to_file.setToolTip("勾选后会创建或扩展输入文件中的专用补丁节，并把入口/代码洞都写回输入文件。")
        self.write_to_file.stateChanged.connect(self._on_text_changed)
        toolbar.addWidget(self.write_to_file)

        self.preview_btn = QtWidgets.QPushButton("预览代码注入", self.dialog)
        self.preview_btn.clicked.connect(self._preview_patch)
        toolbar.addWidget(self.preview_btn)
        root.addLayout(toolbar)

        buttons = QtWidgets.QDialogButtonBox(self.dialog)
        self.apply_btn = buttons.addButton("应用", QtWidgets.QDialogButtonBox.AcceptRole)
        self.cancel_btn = buttons.addButton("取消", QtWidgets.QDialogButtonBox.RejectRole)
        self.apply_btn.clicked.connect(self._apply_patch)
        self.cancel_btn.clicked.connect(self.dialog.reject)
        root.addWidget(buttons)

        self.editor.setPlainText(self.original_asm_text)
        self.status.setText("已载入当前所选汇编。可直接在编辑框中自由修改。")
        self.editor.textChanged.connect(self._on_text_changed)
        self._refresh_context_panel()
        _debug_log(
            "trampoline_dialog.open",
            trace_id=self.trace_id,
            start_ea="0x%X" % self.start_ea,
            region_size=self.region_size,
            include_original=self.include_original.isChecked(),
            original_asm=self.original_asm_text,
            input_file=_input_file_path(),
        )

    def _current_text(self):
        """Return the current editor text."""
        return self.editor.toPlainText().strip()

    def _load_original_into_editor(self):
        """Reload the currently selected original instructions into the editor."""
        self.include_original.setChecked(False)
        self.editor.setPlainText(self.original_asm_text)
        self.status.setText("已重新载入当前所选汇编。可直接修改顺序和内容。")

    def _build_editor_example_lines(self):
        """Build a CE-style multiline example for the right-side hint panel."""
        selected = []
        for entry in self.original_entries[:2]:
            line = _sanitize_asm_line(entry.get("text") or entry.get("asm") or "")
            if line:
                selected.append(line)

        lines = [
            "例子:",
            "编辑框就相当于 CE 里的 `newmem:` 主体。",
            "末尾跳回会自动追加，不需要自己写 `jmp returnhere`。",
            "",
        ]
        if len(selected) >= 2:
            lines.extend(
                [
                    "当前选中:",
                    selected[0],
                    selected[1],
                    "",
                    "你可以直接改成:",
                    "mov eax, 1",
                    selected[0],
                    "mov eax, 2",
                    selected[1],
                ]
            )
        elif selected:
            lines.extend(
                [
                    "当前选中:",
                    selected[0],
                    "",
                    "你可以直接改成:",
                    "mov eax, 1",
                    selected[0],
                ]
            )
        else:
            lines.extend(
                [
                    "你可以直接写成:",
                    "mov eax, 1",
                    "call my_hook",
                ]
            )
        return lines

    def _on_text_changed(self):
        """Drop stale preview state when editor options change."""
        self.preview_plan = None
        self.preview_text = ""
        if self._current_text() or self.include_original.isChecked():
            if self._current_text() == self.original_asm_text and not self.include_original.isChecked():
                self.status.setText("已载入当前所选汇编。可直接在编辑框中自由修改。")
            else:
                self.status.setText("编辑中。点击“预览代码注入”或直接“应用”。")
        else:
            self.status.setText("当前代码洞内容为空。")
        self._refresh_context_panel()

    def _build_hint_text(self):
        """Build the right-side summary for the trampoline patch."""
        lines = [
            "覆盖原始指令:",
        ]
        for index, entry in enumerate(self.original_entries, 1):
            lines.append("%d. 0x%X: %s" % (index, entry["ea"], entry["text"] or "(unknown)"))

        lines.append("")
        lines.append("入口补丁:")
        lines.append("- 原地址将写入 `jmp code_cave`，其余字节自动补 NOP")
        lines.append("- 返回地址: 0x%X" % (self.start_ea + self.region_size))
        lines.append(
            "- 当前模式: %s"
            % ("末尾自动补齐未保留的原指令" if self.include_original.isChecked() else "仅按编辑框中的完整顺序执行")
        )
        lines.append("- 存储位置: %s" % ("输入文件内 `%s` 节" % PATCH_FILE_SECTION_NAME if self.write_to_file.isChecked() else "仅 IDB 内 .patch 段"))

        lines.append("")
        lines.append("编辑方式:")
        lines.append("- 编辑框默认已载入当前所选原始汇编")
        lines.append("- 你可以直接插入、删除、重排、改写这些指令")
        lines.append("- 结尾回跳 `jmp returnhere` 会自动追加，不需要自己写")

        custom_text = self._current_text()
        if custom_text:
            lines.append("")
            lines.append("当前代码洞主体:")
            for line in custom_text.splitlines():
                stripped = _sanitize_asm_line(line)
                if stripped:
                    lines.append("- %s" % stripped)
        else:
            lines.append("")
            lines.append("当前代码洞主体:")
            lines.append("- (empty)")

        if self.preview_plan is not None and self.preview_text == custom_text:
            lines.append("")
            lines.append("预览结果:")
            lines.append("- 代码洞段: %s" % (self.preview_plan.get("segment_name") or _segment_name(self.preview_plan.get("segment"))))
            lines.append("- 代码洞起始: 0x%X" % self.preview_plan["cave_start"])
            if self.preview_plan.get("storage_mode") == "file_section":
                lines.append("- 代码洞来源: 输入文件里的专用补丁节 `%s`" % PATCH_FILE_SECTION_NAME)
            else:
                lines.append("- 代码洞来源: IDB 专用 .patch 段")
            lines.append("- 入口机器码: %s" % _format_bytes_hex(self.preview_plan["entry_bytes"]))
            lines.append("- 代码洞总长度: %d bytes" % len(self.preview_plan["cave_bytes"]))
            if self.preview_plan["risk_notes"]:
                lines.append("")
                lines.append("风险提示:")
                for note in self.preview_plan["risk_notes"]:
                    lines.append("- %s" % note)
        else:
            lines.append("")
            lines.append("预览结果:")
            lines.append("- 当前尚未生成新的代码洞预览")

        lines.append("")
        lines.append("注意:")
        lines.append("- 不写入输入文件时，默认在 IDB 内新增/复用 `%s` 段" % PATCH_SEGMENT_NAME)
        lines.append("- 写入输入文件时，默认创建/扩展 `%s` 节；不再依赖现成 code cave" % PATCH_FILE_SECTION_NAME)
        lines.append("- 高级用法仍可选 `{{orig}}` / `{{orig:N}}`，但默认不需要")
        lines.append("- 代码洞更接近 CE 的 `newmem` 主体：只写你想执行的完整顺序即可")
        lines.append("- 若启用末尾自动补齐原指令，控制流/RIP 相对寻址仍需人工确认")
        lines.append("")
        lines.extend(self._build_editor_example_lines())
        return "\n".join(lines)

    def _refresh_context_panel(self):
        """Refresh the trampoline summary panel."""
        self.hint_panel.setPlainText(self._build_hint_text())

    def _compute_plan(self):
        """Assemble and preview the trampoline plan."""
        custom_text = self._current_text()
        include_original = self.include_original.isChecked()
        if not custom_text and not include_original:
            raise RuntimeError("当前既没有自定义代码，也没有启用原指令回放。")
        return _preview_trampoline_plan(
            self.start_ea,
            self.region_size,
            custom_text,
            self.original_entries,
            include_original,
            write_to_file=self.write_to_file.isChecked(),
        )

    def _preview_patch(self):
        """Preview cave allocation and trampoline bytes."""
        try:
            _debug_log(
                "trampoline_dialog.preview.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                include_original=self.include_original.isChecked(),
                custom_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
            )
            self.preview_plan = self._compute_plan()
            self.preview_text = self._current_text()
            self.status.setText(
                "预览成功: 入口 %d bytes | 代码洞 %d bytes"
                % (len(self.preview_plan["entry_bytes"]), len(self.preview_plan["cave_bytes"]))
            )
            _debug_log(
                "trampoline_dialog.preview.success",
                trace_id=self.trace_id,
                cave_start="0x%X" % self.preview_plan["cave_start"],
                cave_size=len(self.preview_plan["cave_bytes"]),
                entry_size=len(self.preview_plan["entry_bytes"]),
                write_to_file=self.write_to_file.isChecked(),
            )
        except Exception as exc:
            self.preview_plan = None
            self.preview_text = ""
            self.status.setText("预览失败: %s" % exc)
            _debug_log_exception(
                "trampoline_dialog.preview.failure",
                exc,
                trace_id=self.trace_id,
                include_original=self.include_original.isChecked(),
                custom_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
            )
        self._refresh_context_panel()

    def _apply_patch(self):
        """Write the trampoline entry and cave code to the database."""
        transaction = None
        applied_count = 0
        try:
            _debug_log(
                "trampoline_dialog.apply.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                include_original=self.include_original.isChecked(),
                custom_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
            )
            plan = self._compute_plan()
            if plan["risk_notes"]:
                details = "\n".join("- %s" % note for note in plan["risk_notes"][:8])
                if len(plan["risk_notes"]) > 8:
                    details += "\n- ..."
                answer = ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_YES,
                    "检测到本次代码注入存在需要人工确认的风险：\n\n%s\n\n是否继续应用跳板补丁？"
                    % details,
                )
                if answer != ida_kernwin.ASKBTN_YES:
                    return

            cave_start = plan["cave_start"]
            cave_end = plan["cave_end"]
            file_path = ""
            if plan.get("storage_mode") == "idb":
                seg = _ensure_patch_segment(len(plan["cave_bytes"]) + PATCH_STUB_ALIGN)
                new_cave_start = _next_patch_cursor(seg)
                if new_cave_start != plan["cave_start"]:
                    plan = _preview_trampoline_plan(
                        self.start_ea,
                        self.region_size,
                        self._current_text(),
                        self.original_entries,
                        self.include_original.isChecked(),
                        write_to_file=self.write_to_file.isChecked(),
                    )
                    cave_start = plan["cave_start"]
                    cave_end = plan["cave_end"]
            elif plan.get("storage_mode") == "file_section":
                required_total = (
                    (plan["cave_start"] - plan.get("alloc_base_ea", plan["cave_start"]))
                    + len(plan["cave_bytes"])
                    + PATCH_STUB_ALIGN
                )
                file_info = _prepare_file_patch_segment(required_total, apply_changes=True)
                seg = file_info.get("segment")
                new_cave_start = _next_patch_cursor(seg) if seg is not None else plan["cave_start"]
                if new_cave_start != plan["cave_start"]:
                    plan = _preview_trampoline_plan(
                        self.start_ea,
                        self.region_size,
                        self._current_text(),
                        self.original_entries,
                        self.include_original.isChecked(),
                        write_to_file=self.write_to_file.isChecked(),
                    )
                    cave_start = plan["cave_start"]
                    cave_end = plan["cave_end"]

            transaction = _begin_patch_transaction(
                "trampoline",
                "代码注入",
                self.start_ea,
                trace_id=self.trace_id,
                meta={
                    "start_ea": self.start_ea,
                    "region_size": self.region_size,
                    "write_to_file": self.write_to_file.isChecked(),
                    "cave_start": cave_start,
                    "cave_end": cave_end,
                    "owner_ea": self.start_ea,
                },
            )
            _record_transaction_operation(
                transaction,
                cave_start,
                plan["cave_bytes"],
                write_to_file=self.write_to_file.isChecked(),
                note="trampoline_cave",
            )
            file_path = _apply_code_patch(
                cave_start,
                plan["cave_bytes"],
                write_to_file=self.write_to_file.isChecked(),
            )
            applied_count = 1
            idc.set_name(cave_start, "patch_cave_%X" % self.start_ea, idc.SN_NOWARN)
            if not _attach_cave_to_owner_function(self.start_ea, cave_start, cave_end):
                _debug_log(
                    "trampoline.attach_tail.failure",
                    owner="0x%X" % self.start_ea,
                    cave_start="0x%X" % cave_start,
                    cave_end="0x%X" % cave_end,
                )

            entry_patch = plan["entry_bytes"]
            if len(entry_patch) < self.region_size:
                entry_patch += _build_nop_bytes(self.start_ea + len(entry_patch), self.region_size - len(entry_patch))
            _record_transaction_operation(
                transaction,
                self.start_ea,
                entry_patch,
                write_to_file=self.write_to_file.isChecked(),
                note="trampoline_entry",
            )
            _apply_code_patch(
                self.start_ea,
                entry_patch,
                write_to_file=self.write_to_file.isChecked(),
            )
            applied_count = 2
            _commit_patch_transaction(transaction)
            ida_auto.auto_wait()
            if not _attach_cave_to_owner_function(self.start_ea, cave_start, cave_end):
                _debug_log(
                    "trampoline.attach_tail.failure.post_entry",
                    owner="0x%X" % self.start_ea,
                    cave_start="0x%X" % cave_start,
                    cave_end="0x%X" % cave_end,
                )

            if self.write_to_file.isChecked():
                ida_kernwin.msg(
                    "[%s] 代码注入完成: 0x%X -> 0x%X，覆盖 %d bytes，代码洞 %d bytes，并同步到输入文件: %s。\n"
                    % (PLUGIN_NAME, self.start_ea, cave_start, self.region_size, len(plan["cave_bytes"]), file_path)
                )
            else:
                ida_kernwin.msg(
                    "[%s] 代码注入完成: 0x%X -> 0x%X，覆盖 %d bytes，代码洞 %d bytes。\n"
                    % (PLUGIN_NAME, self.start_ea, cave_start, self.region_size, len(plan["cave_bytes"]))
                )
            _debug_log(
                "trampoline_dialog.apply.success",
                trace_id=self.trace_id,
                cave_start="0x%X" % cave_start,
                cave_size=len(plan["cave_bytes"]),
                entry_size=len(plan["entry_bytes"]),
                write_to_file=self.write_to_file.isChecked(),
                file_path=file_path,
            )
            self.preview_plan = plan
            self.preview_text = self._current_text()
            self.dialog.accept()
        except Exception as exc:
            try:
                _rollback_partial_transaction(transaction, applied_count)
            except Exception as rollback_exc:
                _debug_log_exception(
                    "trampoline_dialog.partial_rollback.failure",
                    rollback_exc,
                    trace_id=self.trace_id,
                )
            _debug_log_exception(
                "trampoline_dialog.apply.failure",
                exc,
                trace_id=self.trace_id,
                include_original=self.include_original.isChecked(),
                custom_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
            )
            ida_kernwin.warning("代码注入失败:\n%s" % exc)

    def exec(self):
        """Show the trampoline dialog modelessly so IDA stays interactive."""
        return _show_modeless_dialog(self)


class AssembleActionHandler(ida_kernwin.action_handler_t):
    """Action handler for the '修改汇编' popup command."""

    def activate(self, ctx):
        """Open the assemble dialog."""
        try:
            AssemblePatchDialog(ctx).exec()
        except Exception as exc:
            ida_kernwin.warning("打开 Assemble 窗口失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        """Enable the action only inside the disassembly view."""
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class TrampolineActionHandler(ida_kernwin.action_handler_t):
    """Action handler for the CE-style trampoline/code-cave command."""

    def activate(self, ctx):
        """Open the trampoline patch dialog."""
        try:
            TrampolinePatchDialog(ctx).exec()
        except Exception as exc:
            ida_kernwin.warning("打开代码注入窗口失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        """Enable the action only inside the disassembly view."""
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class NopActionHandler(ida_kernwin.action_handler_t):
    """Action handler for filling the current range with NOP instructions."""

    def activate(self, ctx):
        """Patch selected instructions or current item with NOP bytes."""
        transaction = None
        applied_count = 0
        try:
            items = list(_selected_items(ctx))
            if not items:
                raise RuntimeError("当前没有可 NOP 的目标。")
            transaction = _begin_patch_transaction(
                "nop",
                "NOP",
                items[0][0],
                meta={"item_count": len(items)},
            )
            patched = 0
            for ea, size in items:
                nop_bytes = _build_nop_bytes(ea, size)
                _record_transaction_operation(
                    transaction,
                    ea,
                    nop_bytes,
                    write_to_file=False,
                    note="nop_fill",
                )
                _apply_code_patch(ea, nop_bytes, write_to_file=False)
                applied_count += 1
                patched += 1
            _commit_patch_transaction(transaction)
            ida_kernwin.msg("[%s] NOP 完成，处理了 %d 个条目。\n" % (PLUGIN_NAME, patched))
        except Exception as exc:
            try:
                _rollback_partial_transaction(transaction, applied_count)
            except Exception as rollback_exc:
                _debug_log_exception("nop.partial_rollback.failure", rollback_exc)
            ida_kernwin.warning("NOP 失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        """Enable the action only inside the disassembly view."""
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class RollbackActionHandler(ida_kernwin.action_handler_t):
    """Action handler that opens the rollback history list."""

    def activate(self, ctx):
        """Open the rollback list dialog."""
        try:
            RollbackHistoryDialog(ctx).exec()
        except Exception as exc:
            _debug_log_exception("rollback.failure", exc)
            ida_kernwin.warning("回撤失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        """Enable the action only inside the disassembly view."""
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class ShortcutSettingsActionHandler(ida_kernwin.action_handler_t):
    """Action handler that opens the shortcut settings dialog."""

    def activate(self, ctx):
        """Open the shortcut settings dialog."""
        try:
            ShortcutSettingsDialog().exec()
        except Exception as exc:
            _debug_log_exception("shortcut_settings.failure", exc)
            ida_kernwin.warning("打开快捷键设置失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        """Keep shortcut settings available from global menu entry points."""
        return ida_kernwin.AST_ENABLE_ALWAYS


class PopupHooks(ida_kernwin.UI_Hooks):
    """UI hook that injects plugin actions into IDA's disassembly popup menu."""

    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        """Attach custom actions when the popup belongs to a disassembly widget."""
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return

        ida_kernwin.attach_action_to_popup(
            widget,
            popup,
            ACTION_ASSEMBLE,
            None,
            ida_kernwin.SETMENU_APP | ida_kernwin.SETMENU_ENSURE_SEP,
        )
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_TRAMPOLINE)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NOP)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_ROLLBACK)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_SHORTCUTS)


class AsmPatchPopupPlugin(ida_idaapi.plugin_t):
    """IDA plugin entry object responsible for action registration and hooks."""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = "ida_patch_pro patch actions for the disassembly view."
    help = "Use ida_patch_pro from the disassembly popup or Edit/Patch program menu."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self):
        """Initialize plugin-owned UI hook state."""
        super().__init__()
        self.hooks = None

    def init(self):
        """Register actions and start popup hook injection."""
        shortcuts = _load_action_shortcuts()
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_ASSEMBLE,
                "修改汇编",
                AssembleActionHandler(),
                _shortcut_or_none(shortcuts.get(ACTION_ASSEMBLE)),
                "调用 IDA 自带的 Assemble 补丁功能",
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_TRAMPOLINE,
                "代码注入",
                TrampolineActionHandler(),
                _shortcut_or_none(shortcuts.get(ACTION_TRAMPOLINE)),
                "创建代码洞并写入跳板补丁",
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_NOP,
                "NOP",
                NopActionHandler(),
                _shortcut_or_none(shortcuts.get(ACTION_NOP)),
                "将当前指令或选中范围填充为 NOP",
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_ROLLBACK,
                "补丁回撤列表",
                RollbackActionHandler(),
                _shortcut_or_none(shortcuts.get(ACTION_ROLLBACK)),
                "打开补丁事务列表，并手动选择要回撤的那一次",
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_SHORTCUTS,
                "快捷键设置",
                ShortcutSettingsActionHandler(),
                _shortcut_or_none(shortcuts.get(ACTION_SHORTCUTS)),
                "配置插件动作的快捷键",
            )
        )

        _detach_main_menu_actions()
        _attach_main_menu_actions()
        self.hooks = PopupHooks()
        self.hooks.hook()
        ida_kernwin.msg("[%s] 已加载。\n" % PLUGIN_NAME)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Support IDA's direct plugin run entry point."""
        try:
            ShortcutSettingsDialog().exec()
        except Exception as exc:
            _debug_log_exception("shortcut_settings.run.failure", exc)
            ida_kernwin.warning("打开快捷键设置失败:\n%s" % exc)

    def term(self):
        """Unhook UI state and unregister actions on plugin unload."""
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None
        _detach_main_menu_actions()
        ida_kernwin.unregister_action(ACTION_ASSEMBLE)
        ida_kernwin.unregister_action(ACTION_TRAMPOLINE)
        ida_kernwin.unregister_action(ACTION_NOP)
        ida_kernwin.unregister_action(ACTION_ROLLBACK)
        ida_kernwin.unregister_action(ACTION_SHORTCUTS)


def PLUGIN_ENTRY():
    """Standard IDA plugin entry point."""
    return AsmPatchPopupPlugin()
