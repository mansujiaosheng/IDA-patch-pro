"""Logging helpers for ida_patch_pro."""

import time
import traceback

from .runtime.paths import test_log_path


def format_bytes_hex(buf):
    """Format raw bytes as upper-case hex pairs for UI/log display."""
    if not buf:
        return "(none)"
    return " ".join("%02X" % b for b in buf)


def _log_preview_text(value, limit=600):
    """Format a value into a single-line log fragment."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = format_bytes_hex(value)
    else:
        text = str(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > limit:
        text = "%s...(truncated %d chars)" % (text[:limit], len(text) - limit)
    return text


def debug_log(event, **fields):
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
        with open(test_log_path(), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def debug_log_exception(event, exc, **fields):
    """Record an exception and traceback without affecting plugin behavior."""
    fields = dict(fields)
    fields["error"] = "%s: %s" % (exc.__class__.__name__, exc)
    debug_log(event, **fields)
    try:
        tb = traceback.format_exc()
    except Exception:
        tb = ""
    if tb and tb.strip() != "NoneType: None":
        debug_log("%s.traceback" % event, traceback=tb)


def make_trace_id(prefix, ea):
    """Create a short identifier so one test action can be correlated in logs."""
    return "%s-%X-%d" % (prefix, ea, int(time.time() * 1000))
