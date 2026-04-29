"""Action handlers, popup hooks, and menu attachment."""

import ida_kernwin

from .constants import (
    ACTION_ASSEMBLE,
    ACTION_EXPORT_PACKAGE,
    ACTION_FILL_RANGE,
    ACTION_IMPORT_PACKAGE,
    ACTION_NOP,
    ACTION_ROLLBACK,
    ACTION_SEARCH,
    ACTION_SHORTCUTS,
    ACTION_SHORTCUT_SPECS,
    ACTION_STRING,
    ACTION_TRAMPOLINE,
    MAIN_MENU_LABEL,
    MAIN_MENU_NAME,
    MAIN_MENU_PARENT_PATH,
    MAIN_MENU_PATH,
    PLUGIN_NAME,
    POPUP_MENU_PATH,
)
from .logging_utils import debug_log_exception
from .patching.bytes_patch import apply_code_patch, build_nop_bytes
from .patching.history_store import load_action_shortcuts, shortcut_or_none
from .patching.package_io import (
    export_patch_package_via_dialog,
    import_patch_package_via_dialog,
)
from .patching.rollback import rollback_partial_transaction
from .patching.selection import selected_items
from .patching.transactions import (
    begin_patch_transaction,
    commit_patch_transaction,
    record_transaction_operation,
)
from .ui.assemble_dialog import AssemblePatchDialog
from .ui.fill_range_dialog import FillRangeDialog
from .ui.rollback_dialog import RollbackHistoryDialog
from .ui.search_dialog import AssemblySearchDialog
from .ui.shortcut_dialog import ShortcutSettingsDialog
from .ui.string_dialog import StringPatchDialog
from .ui.trampoline_dialog import TrampolinePatchDialog


def iter_plugin_action_names():
    """Yield every registered plugin action name in display order."""
    for action_name, _label, _default_shortcut in ACTION_SHORTCUT_SPECS:
        yield action_name


def attach_main_menu_actions():
    """Expose plugin actions in a dedicated submenu under Edit/Patch program."""
    creator = getattr(ida_kernwin, "create_menu", None)
    attacher = getattr(ida_kernwin, "attach_action_to_menu", None)
    if creator is None or attacher is None:
        return False
    try:
        creator(MAIN_MENU_NAME, MAIN_MENU_LABEL, MAIN_MENU_PARENT_PATH)
        attached_any = False
        for action_name in iter_plugin_action_names():
            if attacher(MAIN_MENU_PATH, action_name, ida_kernwin.SETMENU_APP):
                attached_any = True
        return attached_any
    except Exception as exc:
        debug_log_exception("menu.attach.failure", exc, menu_path=MAIN_MENU_PATH)
        return False


def detach_main_menu_actions():
    """Remove previously attached top-menu actions and the custom submenu."""
    detacher = getattr(ida_kernwin, "detach_action_from_menu", None)
    deleter = getattr(ida_kernwin, "delete_menu", None)
    try:
        if detacher is not None:
            for action_name in iter_plugin_action_names():
                detacher(MAIN_MENU_PATH, action_name)
        if deleter is not None:
            deleter(MAIN_MENU_NAME)
    except Exception as exc:
        debug_log_exception("menu.detach.failure", exc, menu_path=MAIN_MENU_PATH)


class AssembleActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            AssemblePatchDialog(ctx).exec()
        except Exception as exc:
            ida_kernwin.warning("打开 Assemble 窗口失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class TrampolineActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            TrampolinePatchDialog(ctx).exec()
        except Exception as exc:
            ida_kernwin.warning("打开代码注入窗口失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class StringActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            StringPatchDialog(ctx).exec()
        except Exception as exc:
            debug_log_exception("string_dialog.open.failure", exc)
            ida_kernwin.warning("打开修改字符串窗口失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class NopActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        transaction = None
        applied_count = 0
        try:
            items = list(selected_items(ctx))
            if not items:
                raise RuntimeError("当前没有可 NOP 的目标。")

            transaction = begin_patch_transaction(
                "nop",
                "NOP",
                items[0][0],
                meta={"item_count": len(items)},
            )

            patched = 0
            for ea, size in items:
                nop_bytes = build_nop_bytes(ea, size)
                record_transaction_operation(
                    transaction,
                    ea,
                    nop_bytes,
                    write_to_file=False,
                    note="nop_fill",
                )
                apply_code_patch(ea, nop_bytes, write_to_file=False)
                applied_count += 1
                patched += 1

            commit_patch_transaction(transaction)
            ida_kernwin.msg("[%s] NOP 完成，处理了 %d 个条目。\n" % (PLUGIN_NAME, patched))
        except Exception as exc:
            try:
                rollback_partial_transaction(transaction, applied_count)
            except Exception as rollback_exc:
                debug_log_exception("nop.partial_rollback.failure", rollback_exc)
            ida_kernwin.warning("NOP 失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class FillRangeActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            FillRangeDialog(ctx).exec()
        except Exception as exc:
            debug_log_exception("fill_range.open.failure", exc)
            ida_kernwin.warning("打开 Fill Range 窗口失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class SearchActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            AssemblySearchDialog(ctx).exec()
        except Exception as exc:
            debug_log_exception("assembly_search.open.failure", exc)
            ida_kernwin.warning("打开汇编搜索窗口失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class RollbackActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            RollbackHistoryDialog(ctx).exec()
        except Exception as exc:
            debug_log_exception("rollback.failure", exc)
            ida_kernwin.warning("回撤失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class ExportPackageActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            export_patch_package_via_dialog()
        except Exception as exc:
            debug_log_exception("export_package.failure", exc)
            ida_kernwin.warning("导出补丁包失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_ENABLE_ALWAYS


class ImportPackageActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            import_patch_package_via_dialog()
        except Exception as exc:
            debug_log_exception("import_package.failure", exc)
            ida_kernwin.warning("导入补丁包失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_ENABLE_ALWAYS


class ShortcutSettingsActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            ShortcutSettingsDialog().exec()
        except Exception as exc:
            debug_log_exception("shortcut_settings.failure", exc)
            ida_kernwin.warning("打开快捷键设置失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class PopupHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return

        ida_kernwin.attach_action_to_popup(
            widget,
            popup,
            ACTION_ASSEMBLE,
            POPUP_MENU_PATH,
            ida_kernwin.SETMENU_APP | ida_kernwin.SETMENU_ENSURE_SEP,
        )
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_STRING, POPUP_MENU_PATH)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_TRAMPOLINE, POPUP_MENU_PATH)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NOP, POPUP_MENU_PATH)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_FILL_RANGE, POPUP_MENU_PATH)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_SEARCH, POPUP_MENU_PATH)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_ROLLBACK, POPUP_MENU_PATH)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_EXPORT_PACKAGE, POPUP_MENU_PATH)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_IMPORT_PACKAGE, POPUP_MENU_PATH)
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_SHORTCUTS, POPUP_MENU_PATH)


def register_actions():
    shortcuts = load_action_shortcuts()

    for action_name in iter_plugin_action_names():
        try:
            ida_kernwin.unregister_action(action_name)
        except Exception:
            pass

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_ASSEMBLE,
            "修改汇编",
            AssembleActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_ASSEMBLE)),
            "调用 IDA 自带的 Assemble 补丁功能",
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_TRAMPOLINE,
            "代码注入",
            TrampolineActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_TRAMPOLINE)),
            "创建代码洞并写入跳板补丁",
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_STRING,
            "修改字符串",
            StringActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_STRING)),
            "把文本编码成数据字节写入，并可定义为字符串",
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NOP,
            "NOP",
            NopActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_NOP)),
            "将当前指令或选中范围填充为 NOP",
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_FILL_RANGE,
            "Fill Range",
            FillRangeActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_FILL_RANGE)),
            "重复汇编当前输入并填满指定范围",
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_SEARCH,
            "汇编搜索",
            SearchActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_SEARCH)),
            "按汇编模式搜索当前数据库中的匹配位置",
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_ROLLBACK,
            "补丁回撤列表",
            RollbackActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_ROLLBACK)),
            "打开补丁事务列表，并手动选择要回撤的那一次",
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_EXPORT_PACKAGE,
            "导出补丁包",
            ExportPackageActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_EXPORT_PACKAGE)),
            "把当前 active 补丁事务导出成可分享补丁包",
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_IMPORT_PACKAGE,
            "导入补丁包",
            ImportPackageActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_IMPORT_PACKAGE)),
            "导入补丁包并把补丁重放到当前 IDB",
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_SHORTCUTS,
            "快捷键设置",
            ShortcutSettingsActionHandler(),
            shortcut_or_none(shortcuts.get(ACTION_SHORTCUTS)),
            "配置插件动作的快捷键",
        )
    )


def unregister_actions():
    for action_name in iter_plugin_action_names():
        try:
            ida_kernwin.unregister_action(action_name)
        except Exception:
            pass
