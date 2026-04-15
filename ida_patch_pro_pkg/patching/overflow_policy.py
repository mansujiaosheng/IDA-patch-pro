"""Persisted policy for handling oversized inline assembly patches."""

from .history_store import load_plugin_settings, save_plugin_settings

ASSEMBLE_OVERSIZE_POLICY_KEY = "assemble_oversize_policy"
ASSEMBLE_OVERSIZE_ASK = "ask"
ASSEMBLE_OVERSIZE_INLINE = "inline"
ASSEMBLE_OVERSIZE_TRAMPOLINE = "trampoline"
_VALID_POLICIES = {
    ASSEMBLE_OVERSIZE_ASK,
    ASSEMBLE_OVERSIZE_INLINE,
    ASSEMBLE_OVERSIZE_TRAMPOLINE,
}


def normalize_oversize_policy(value):
    """Normalize one saved oversize policy value."""
    value = (value or "").strip().lower()
    if value in _VALID_POLICIES:
        return value
    return ASSEMBLE_OVERSIZE_ASK


def load_oversize_policy():
    """Load the persisted oversize-handling policy for normal Assemble patches."""
    settings = load_plugin_settings()
    return normalize_oversize_policy(settings.get(ASSEMBLE_OVERSIZE_POLICY_KEY))


def save_oversize_policy(policy):
    """Persist the oversize-handling policy for future Assemble actions."""
    settings = load_plugin_settings()
    settings[ASSEMBLE_OVERSIZE_POLICY_KEY] = normalize_oversize_policy(policy)
    save_plugin_settings(settings)


def oversize_policy_label(policy):
    """Return a short user-facing label for one oversize policy."""
    policy = normalize_oversize_policy(policy)
    if policy == ASSEMBLE_OVERSIZE_INLINE:
        return "继续覆盖"
    if policy == ASSEMBLE_OVERSIZE_TRAMPOLINE:
        return "改用代码注入"
    return "每次询问"
