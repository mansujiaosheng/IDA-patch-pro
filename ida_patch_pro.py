"""ida_patch_pro bootstrap.

IDA still discovers the plugin via this root file, while the actual
implementation lives in the `ida_patch_pro_pkg` package directory.
"""

import importlib
import sys


def _reload_or_import(module_name):
    """Import a sibling module, reloading it when already cached."""
    module = sys.modules.get(module_name)
    if module is not None:
        return importlib.reload(module)
    return importlib.import_module(module_name)


_pkg = _reload_or_import("ida_patch_pro_pkg")


def PLUGIN_ENTRY():
    """Delegate to the reloaded package entry."""
    return _pkg.PLUGIN_ENTRY()
