"""Shared constants for ida_patch_pro."""

import re

PLUGIN_NAME = "ida_patch_pro"

ACTION_ASSEMBLE = "ida_patch_pro:assemble"
ACTION_NOP = "ida_patch_pro:nop"
ACTION_TRAMPOLINE = "ida_patch_pro:trampoline"
ACTION_FILL_RANGE = "ida_patch_pro:fill_range"
ACTION_SEARCH = "ida_patch_pro:search"
ACTION_ROLLBACK = "ida_patch_pro:rollback"
ACTION_SHORTCUTS = "ida_patch_pro:shortcut_settings"
ACTION_EXPORT_PACKAGE = "ida_patch_pro:export_package"
ACTION_IMPORT_PACKAGE = "ida_patch_pro:import_package"

MAIN_MENU_NAME = "ida_patch_pro_menu"
MAIN_MENU_LABEL = PLUGIN_NAME
MAIN_MENU_PARENT_PATH = "Edit/Patch program/"
MAIN_MENU_PATH = "%s%s/" % (MAIN_MENU_PARENT_PATH, MAIN_MENU_LABEL)
POPUP_MENU_LABEL = "ida-patch-pro"
POPUP_MENU_PATH = "%s/" % POPUP_MENU_LABEL

PATCH_SEGMENT_NAME = ".patch"
PATCH_FILE_SECTION_NAME = ".patchf"
PATCH_SEGMENT_CLASS = "CODE"
PATCH_SEGMENT_DEFAULT_SIZE = 0x2000
PATCH_STUB_ALIGN = 0x10
TEST_LOG_FILENAME = "ida_patch_pro.test.log"
HISTORY_FILENAME = "ida_patch_pro.history.json"
SETTINGS_FILENAME = "ida_patch_pro.settings.json"
PATCH_PACKAGE_FILENAME_SUFFIX = ".idppatch.json"
FILE_CAVE_FILL_BYTES = {0x00, 0x90, 0xCC}
PE_SECTION_CHARACTERISTICS_RX = 0x60000020
TRAMPOLINE_ORIG_MARKER_RE = re.compile(r"(?is)^\{\{\s*orig(?:\s*:\s*(all|\d+))?\s*\}\}$")


ACTION_SHORTCUT_SPECS = [
    (ACTION_ASSEMBLE, "修改汇编", "Ctrl+Alt+A"),
    (ACTION_TRAMPOLINE, "代码注入", "Ctrl+Alt+T"),
    (ACTION_NOP, "NOP", "Ctrl+Alt+N"),
    (ACTION_FILL_RANGE, "Fill Range", "Ctrl+Alt+F"),
    (ACTION_SEARCH, "汇编搜索", "Ctrl+Alt+S"),
    (ACTION_ROLLBACK, "补丁回撤列表", "Ctrl+Alt+R"),
    (ACTION_EXPORT_PACKAGE, "导出补丁包", "Ctrl+Alt+E"),
    (ACTION_IMPORT_PACKAGE, "导入补丁包", "Ctrl+Alt+I"),
    (ACTION_SHORTCUTS, "快捷键设置", ""),
]
