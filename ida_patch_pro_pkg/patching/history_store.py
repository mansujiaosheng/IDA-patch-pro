"""History/settings JSON storage and shortcut persistence."""

import json

import ida_kernwin

from ..constants import ACTION_SHORTCUT_SPECS
from ..logging_utils import debug_log_exception
from ..runtime.paths import history_file_path, settings_file_path


def load_plugin_settings():
    """Load plugin settings from disk."""
    path = settings_file_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        debug_log_exception("settings.load.failure", exc, path=path)
        return {}
    return data if isinstance(data, dict) else {}


def save_plugin_settings(data):
    """Persist plugin settings to disk."""
    with open(settings_file_path(), "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def normalize_shortcut_text(value):
    """Normalize one shortcut string for storage and registration."""
    return " ".join((value or "").strip().split())


def default_action_shortcuts():
    """Return the built-in action shortcut map."""
    return {action_name: default_shortcut for action_name, _label, default_shortcut in ACTION_SHORTCUT_SPECS}


def load_action_shortcuts():
    """Load configured shortcuts, falling back to built-in defaults."""
    shortcuts = default_action_shortcuts()
    raw = load_plugin_settings().get("shortcuts")
    if isinstance(raw, dict):
        for action_name in shortcuts:
            if action_name not in raw:
                continue
            shortcuts[action_name] = normalize_shortcut_text(raw.get(action_name))
    return shortcuts


def save_action_shortcuts(shortcuts):
    """Persist action shortcuts to the plugin settings file."""
    settings = load_plugin_settings()
    settings["shortcuts"] = {
        action_name: normalize_shortcut_text(shortcuts.get(action_name))
        for action_name, _label, _default_shortcut in ACTION_SHORTCUT_SPECS
    }
    save_plugin_settings(settings)


def shortcut_or_none(value):
    """Convert an empty shortcut string to None for IDA registration APIs."""
    value = normalize_shortcut_text(value)
    return value or None


def apply_registered_shortcuts(shortcuts):
    """Apply shortcuts to already registered actions when IDA supports it."""
    updater = getattr(ida_kernwin, "update_action_shortcut", None)
    if updater is None:
        return False
    try:
        for action_name, _label, _default_shortcut in ACTION_SHORTCUT_SPECS:
            updater(action_name, shortcut_or_none(shortcuts.get(action_name)))
        return True
    except Exception as exc:
        debug_log_exception("settings.apply_shortcuts.failure", exc)
        return False


def load_patch_history():
    """Load persisted patch transactions from disk."""
    path = history_file_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return []
    except Exception as exc:
        debug_log_exception("history.load.failure", exc, path=path)
        return []
    return data if isinstance(data, list) else []


def save_patch_history(entries):
    """Persist patch transactions to disk."""
    with open(history_file_path(), "w", encoding="utf-8") as fh:
        json.dump(entries, fh, ensure_ascii=False, indent=2)


def delete_patch_history_entry(tx_id):
    """Delete one persisted patch-history entry by transaction id."""
    entries = load_patch_history()
    new_entries = [entry for entry in entries if entry.get("tx_id") != tx_id]
    if len(new_entries) == len(entries):
        return False
    save_patch_history(new_entries)
    return True


def delete_patch_history_entries(tx_ids):
    """Delete multiple persisted patch-history entries by transaction id."""
    wanted = {str(tx_id) for tx_id in (tx_ids or []) if tx_id}
    if not wanted:
        return 0
    entries = load_patch_history()
    new_entries = [entry for entry in entries if str(entry.get("tx_id") or "") not in wanted]
    deleted_count = len(entries) - len(new_entries)
    if deleted_count > 0:
        save_patch_history(new_entries)
    return deleted_count


def clear_patch_history():
    """Delete all persisted patch-history entries."""
    save_patch_history([])
