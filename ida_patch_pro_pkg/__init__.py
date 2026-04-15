"""Package entry for ida_patch_pro."""

import importlib
import sys


def _reload_or_import(module_name):
    """Import a sibling module, reloading it when already cached."""
    full_name = "%s.%s" % (__name__, module_name)
    module = sys.modules.get(full_name)
    if module is not None:
        return importlib.reload(module)
    return importlib.import_module("." + module_name, __name__)


_reload_or_import("data")
_plugin = _reload_or_import("plugin")


def PLUGIN_ENTRY():
    """Delegate to the current plugin module."""
    return _plugin.PLUGIN_ENTRY()
