"""Trampoline/code-cave dialog."""

import ida_kernwin

from ..asm.operands import processor_key, sanitize_asm_line
from ..constants import PLUGIN_NAME
from ..ida_adapter import input_file_path
from ..logging_utils import debug_log, debug_log_exception, format_bytes_hex, make_trace_id
from ..patching.selection import get_entries_for_range, hook_region, join_entry_asm_lines
from ..trampoline.file_storage import file_storage_tooltip_text
from ..trampoline.hints import build_trampoline_hint_text
from ..trampoline.apply import apply_trampoline_patch
from ..trampoline.planner import preview_trampoline_plan
from .common import load_qt, show_modeless_dialog
from .patch_table import (
    COL_ASSEMBLY,
    create_patch_table,
    insert_patch_row,
    install_patch_table_key_filter,
    patch_table_assembly_text,
    remove_selected_patch_rows,
    set_patch_table_rows,
)
from .reference_dialogs import RegisterHelpDialog, SyntaxHelpDialog


class TrampolinePatchDialog:
    """Trampoline/code-cave dialog for CE-style jump patching."""

    def __init__(self, ctx, initial_text=None, initial_include_original=False):
        """Initialize the trampoline dialog from the current disassembly context."""
        _QtCore, QtGui, QtWidgets = load_qt()
        self._QtCore = _QtCore
        self.ctx = ctx
        self.arch_key = processor_key()
        if self.arch_key != "x86/x64":
            raise RuntimeError("当前版本的代码注入仅支持 x86/x64。")

        (
            self.start_ea,
            self.region_size,
            self.region_desc,
            self.has_selection,
        ) = hook_region(ctx, 5)
        self.trace_id = make_trace_id("tramp", self.start_ea)

        self.original_entries = get_entries_for_range(self.start_ea, self.region_size)
        self.original_asm_text = join_entry_asm_lines(self.original_entries)
        self.preview_plan = None
        self.preview_signature = None

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("代码注入 / Patching")
        self.dialog.resize(1220, 600)

        root = QtWidgets.QVBoxLayout(self.dialog)
        font = QtGui.QFont("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)

        self.splitter = QtWidgets.QSplitter(self.dialog)
        self.splitter.setOrientation(_QtCore.Qt.Horizontal)
        self.patch_table = create_patch_table(self.dialog, font, editable_bytes=False)
        install_patch_table_key_filter(
            self.patch_table,
            on_enter=self._insert_row,
            on_delete=self._delete_selected_rows,
            on_space=self._insert_row,
        )
        self.patch_table.itemChanged.connect(self._on_table_item_changed)
        self.splitter.addWidget(self.patch_table)

        self.hint_panel = QtWidgets.QPlainTextEdit(self.dialog)
        self.hint_panel.setReadOnly(True)
        self.hint_panel.setFont(font)
        self.splitter.addWidget(self.hint_panel)
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 2)
        root.addWidget(self.splitter, 1)

        toolbar = QtWidgets.QHBoxLayout()
        self.status = QtWidgets.QLabel("当前未预览代码洞。", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.insert_row_btn = QtWidgets.QPushButton("插入行", self.dialog)
        self.insert_row_btn.clicked.connect(self._insert_row)
        toolbar.addWidget(self.insert_row_btn)

        self.delete_row_btn = QtWidgets.QPushButton("删除行", self.dialog)
        self.delete_row_btn.clicked.connect(self._delete_selected_rows)
        toolbar.addWidget(self.delete_row_btn)

        self.include_original = QtWidgets.QCheckBox("末尾自动补齐未保留的原指令并跳回", self.dialog)
        self.include_original.setChecked(bool(initial_include_original))
        self.include_original.stateChanged.connect(self._on_text_changed)
        toolbar.addWidget(self.include_original)

        self.load_original_btn = QtWidgets.QPushButton("载入原指令", self.dialog)
        self.load_original_btn.clicked.connect(self._load_original_into_table)
        toolbar.addWidget(self.load_original_btn)

        self.write_to_file = QtWidgets.QCheckBox("同时写入输入文件", self.dialog)
        self.write_to_file.setToolTip(file_storage_tooltip_text())
        self.write_to_file.stateChanged.connect(self._on_text_changed)
        toolbar.addWidget(self.write_to_file)

        self.preview_btn = QtWidgets.QPushButton("预览代码注入", self.dialog)
        self.preview_btn.clicked.connect(self._preview_patch)
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

        self.toggle_hint_btn = QtWidgets.QPushButton("隐藏提示", self.dialog)
        self.toggle_hint_btn.clicked.connect(self._toggle_hint_panel)
        toolbar.addWidget(self.toggle_hint_btn)
        root.addLayout(toolbar)

        buttons = QtWidgets.QDialogButtonBox(self.dialog)
        self.apply_btn = buttons.addButton("应用", QtWidgets.QDialogButtonBox.AcceptRole)
        self.cancel_btn = buttons.addButton("取消", QtWidgets.QDialogButtonBox.RejectRole)
        self.apply_btn.clicked.connect(self._apply_patch)
        self.cancel_btn.clicked.connect(self.dialog.reject)
        root.addWidget(buttons)

        initial_table_text = initial_text if initial_text is not None else self.original_asm_text
        set_patch_table_rows(self.patch_table, self._build_body_rows(initial_table_text, None))
        self.status.setText("已载入当前所选汇编。按 Enter/Space/Insert 插入 NOP 行，点击“预览代码注入”刷新。")
        self._refresh_context_panel()
        debug_log(
            "trampoline_dialog.open",
            trace_id=self.trace_id,
            start_ea="0x%X" % self.start_ea,
            region_size=self.region_size,
            include_original=self.include_original.isChecked(),
            original_asm=self.original_asm_text,
            input_file=input_file_path(),
        )

    def _build_syntax_menu(self):
        """Create the quick reference dropdown menu."""
        _QtCore, _QtGui, QtWidgets = load_qt()
        menu = QtWidgets.QMenu(self.dialog)
        current_action = menu.addAction("当前架构: %s" % self.arch_key)
        current_action.triggered.connect(
            lambda checked=False, cat=self.arch_key: self._show_syntax_help(cat)
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
        _QtCore, _QtGui, QtWidgets = load_qt()
        menu = QtWidgets.QMenu(self.dialog)
        current_action = menu.addAction("当前架构: %s" % self.arch_key)
        current_action.triggered.connect(
            lambda checked=False, cat=self.arch_key: self._show_register_help(cat)
        )
        menu.addSeparator()
        for category in ("x86/x64", "ARM/Thumb", "AArch64", "MIPS"):
            action = menu.addAction(category)
            action.triggered.connect(lambda checked=False, cat=category: self._show_register_help(cat))
        return menu

    def _show_register_help(self, category):
        """Open the register help dialog for the selected architecture."""
        RegisterHelpDialog(category, self.dialog).exec()

    def _current_text(self):
        """Return the current custom code text from the editable table."""
        return patch_table_assembly_text(self.patch_table)

    def _current_signature(self):
        """Return the current preview-relevant input signature."""
        return (
            self._current_text(),
            bool(self.include_original.isChecked()),
            bool(self.write_to_file.isChecked()),
        )

    def _insert_row(self):
        """Insert one editable code-cave row."""
        insert_patch_row(self.patch_table, assembly="nop")
        debug_log(
            "trampoline_dialog.insert_row",
            trace_id=self.trace_id,
            row=self.patch_table.currentRow(),
        )
        self._mark_preview_stale(refresh_context=False, refresh_hint=False)
        return True

    def _delete_selected_rows(self):
        """Delete selected table rows and mark preview as stale."""
        if remove_selected_patch_rows(self.patch_table):
            self._on_table_structure_changed()
            return True
        return False

    def _on_table_structure_changed(self):
        """Mark preview stale after rows were inserted or removed."""
        self._mark_preview_stale(refresh_context=False, refresh_hint=False)

    def _toggle_hint_panel(self):
        """Collapse or restore the right-side hint panel."""
        visible = self.hint_panel.isVisible()
        self.hint_panel.setVisible(not visible)
        self.toggle_hint_btn.setText("显示提示" if visible else "隐藏提示")

    def _on_table_item_changed(self, item):
        """Mark preview stale after an assembly cell edit is committed."""
        if item is None or item.column() != COL_ASSEMBLY:
            return
        self._mark_preview_stale(refresh_context=False, refresh_hint=False)

    def _load_original_into_table(self):
        """Reload the currently selected original instructions into the table."""
        self.include_original.setChecked(False)
        set_patch_table_rows(self.patch_table, self._build_body_rows(self.original_asm_text, None))
        self._mark_preview_stale()
        self.status.setText("已重新载入当前所选汇编。可直接修改顺序和内容。")

    def _on_text_changed(self):
        """Drop stale preview state when options change."""
        self._mark_preview_stale(refresh_context=False)

    def _mark_preview_stale(self, refresh_context=True, refresh_hint=True):
        """Drop stale preview state when table or options change."""
        self.preview_plan = None
        self.preview_signature = None
        if self._current_text() or self.include_original.isChecked():
            if self._current_text() == self.original_asm_text and not self.include_original.isChecked():
                self.status.setText("已载入当前所选汇编。Enter 插入 NOP 行，点击预览刷新。")
            else:
                self.status.setText("编辑中。点击“预览代码注入”刷新机器码；Enter 插入 NOP 行。")
        else:
            self.status.setText("当前代码洞内容为空。")
        if refresh_context:
            self._refresh_context_panel()
        elif refresh_hint:
            self._refresh_hint_panel()

    def _build_body_rows(self, text, preview_plan):
        """Build editable body rows for the code-cave table."""
        lines = [sanitize_asm_line(line) for line in text.splitlines()]
        lines = [line for line in lines if line]
        row_count = max(len(lines), 1)
        rows = []
        cave_infos = preview_plan.get("cave_infos") if preview_plan else []
        cave_start = int(preview_plan.get("cave_start") or self.start_ea) if preview_plan else self.start_ea
        current_ea = cave_start
        for index in range(row_count):
            entry = self.original_entries[index] if index < len(self.original_entries) else None
            line = lines[index] if index < len(lines) else ""
            info = cave_infos[index] if index < len(cave_infos or []) else None
            if preview_plan:
                address = current_ea
                row_bytes = info.get("bytes") if info else b""
                current_ea += len(row_bytes or b"")
            elif entry:
                address = int(entry.get("ea") or current_ea)
                row_bytes = entry.get("bytes") or b""
                current_ea = address + len(row_bytes)
            else:
                address = current_ea
                row_bytes = b""
            rows.append(
                {
                    "ea": address,
                    "address": "0x%X" % address,
                    "bytes": format_bytes_hex(row_bytes),
                    "assembly": line or (entry.get("asm") if entry else "") or "",
                    "highlight": index == 0,
                }
            )
        return rows

    def _refresh_context_panel(self):
        """Refresh the editable table and right-side hint panel."""
        current_preview = self.preview_plan if self.preview_signature == self._current_signature() else None
        set_patch_table_rows(
            self.patch_table,
            self._build_body_rows(self._current_text(), current_preview),
        )
        self._refresh_hint_panel(current_preview)

    def _refresh_hint_panel(self, current_preview=None):
        """Refresh only the right-side hint panel."""
        if current_preview is None:
            current_preview = self.preview_plan if self.preview_signature == self._current_signature() else None
        self.hint_panel.setPlainText(
            build_trampoline_hint_text(
                self.original_entries,
                self._current_text(),
                current_preview,
                self.include_original.isChecked(),
                self.write_to_file.isChecked(),
            )
        )

    def _compute_plan(self):
        """Assemble and preview the trampoline plan."""
        custom_text = self._current_text()
        include_original = self.include_original.isChecked()
        if not custom_text and not include_original:
            raise RuntimeError("当前既没有自定义代码，也没有启用原指令回放。")
        return preview_trampoline_plan(
            self.start_ea,
            self.region_size,
            custom_text,
            self.original_entries,
            include_original,
            write_to_file=self.write_to_file.isChecked(),
        )

    def _preview_patch(self, live=False):
        """Preview cave allocation and trampoline bytes."""
        try:
            debug_log(
                "trampoline_dialog.preview.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                include_original=self.include_original.isChecked(),
                custom_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
                live=live,
            )
            self.preview_plan = self._compute_plan()
            self.preview_signature = self._current_signature()
            self.status.setText(
                "%s成功: 入口 %d bytes | 代码洞 %d bytes"
                % (
                    "自动预览" if live else "预览",
                    len(self.preview_plan["entry_bytes"]),
                    len(self.preview_plan["cave_bytes"]),
                )
            )
            debug_log(
                "trampoline_dialog.preview.success",
                trace_id=self.trace_id,
                cave_start="0x%X" % self.preview_plan["cave_start"],
                cave_size=len(self.preview_plan["cave_bytes"]),
                entry_size=len(self.preview_plan["entry_bytes"]),
                write_to_file=self.write_to_file.isChecked(),
                live=live,
            )
        except Exception as exc:
            self.preview_plan = None
            self.preview_signature = None
            self.status.setText("%s失败: %s" % ("自动预览" if live else "预览", exc))
            debug_log_exception(
                "trampoline_dialog.preview.failure",
                exc,
                trace_id=self.trace_id,
                include_original=self.include_original.isChecked(),
                custom_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
                live=live,
            )
        self._refresh_context_panel()

    def _apply_patch(self):
        """Write the trampoline entry and cave code to the database."""
        try:
            debug_log(
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

            result = apply_trampoline_patch(
                self.start_ea,
                self.region_size,
                plan,
                trace_id=self.trace_id,
                plan_builder=self._compute_plan,
                transaction_meta={
                    "trampoline_replay": {
                        "version": 1,
                        "custom_text": self._current_text(),
                        "include_original": bool(self.include_original.isChecked()),
                        "write_to_file": bool(self.write_to_file.isChecked()),
                        "region_size": self.region_size,
                        "original_asm_text": self.original_asm_text,
                        "original_entries": [
                            {
                                "ea": int(entry.get("ea") or 0),
                                "text": entry.get("text") or "",
                                "asm": entry.get("asm") or "",
                                "bytes_hex": bytes(entry.get("bytes") or b"").hex(),
                                "operand_infos": list(entry.get("operand_infos") or []),
                            }
                            for entry in (self.original_entries or [])
                        ],
                    },
                },
            )
            plan = result["plan"]
            cave_start = result["cave_start"]
            cave_end = result["cave_end"]
            file_path = result["file_path"]

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
            debug_log(
                "trampoline_dialog.apply.success",
                trace_id=self.trace_id,
                cave_start="0x%X" % cave_start,
                cave_size=len(plan["cave_bytes"]),
                entry_size=len(plan["entry_bytes"]),
                write_to_file=self.write_to_file.isChecked(),
                file_path=file_path,
            )
            self.preview_plan = plan
            self.preview_signature = self._current_signature()
            self.dialog.accept()
        except Exception as exc:
            debug_log_exception(
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
        return show_modeless_dialog(self)
