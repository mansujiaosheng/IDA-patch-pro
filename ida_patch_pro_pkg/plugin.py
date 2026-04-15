"""Plugin entry and registration lifecycle."""

import ida_idaapi
import ida_kernwin

from .actions import (
    PopupHooks,
    attach_main_menu_actions,
    detach_main_menu_actions,
    register_actions,
    unregister_actions,
)
from .constants import PLUGIN_NAME
from .logging_utils import debug_log_exception
from .ui.shortcut_dialog import ShortcutSettingsDialog


class IdaPatchProPlugin(ida_idaapi.plugin_t):
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
        register_actions()
        detach_main_menu_actions()
        attach_main_menu_actions()
        self.hooks = PopupHooks()
        self.hooks.hook()
        ida_kernwin.msg("[%s] 已加载。\n" % PLUGIN_NAME)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Support IDA's direct plugin run entry point."""
        try:
            ShortcutSettingsDialog().exec()
        except Exception as exc:
            debug_log_exception("shortcut_settings.run.failure", exc)
            ida_kernwin.warning("打开快捷键设置失败:\n%s" % exc)

    def term(self):
        """Unhook UI state and unregister actions on plugin unload."""
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None
        detach_main_menu_actions()
        unregister_actions()


def PLUGIN_ENTRY():
    """Standard IDA plugin entry point."""
    return IdaPatchProPlugin()
