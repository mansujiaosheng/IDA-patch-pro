"""Main assemble dialog."""

import ida_kernwin

from ..asm.assemble import assemble_multiline
from ..asm.hints import build_hint_text
from ..asm.operands import processor_key
from ..constants import PLUGIN_NAME
from ..ida_adapter import input_file_path
from ..logging_utils import debug_log, debug_log_exception, make_trace_id
from ..patching.bytes_patch import apply_code_patch, build_nop_bytes
from ..patching.rollback import rollback_partial_transaction
from ..patching.selection import (
    build_preview_infos_from_entries,
    get_original_entries,
    join_entry_asm_lines,
    patch_region,
)
from ..patching.transactions import (
    begin_patch_transaction,
    commit_patch_transaction,
    record_transaction_operation,
)
from .common import load_qt, show_modeless_dialog
from .reference_dialogs import RegisterHelpDialog, SyntaxHelpDialog


class AssemblePatchDialog:
    """Main assemble/preview/apply dialog opened from the popup menu."""

    def __init__(self, ctx):
        """Initialize dialog state from the current disassembly selection."""
        _QtCore, QtGui, QtWidgets = load_qt()
        self.ctx = ctx
        self.arch_key = processor_key()
        (
            self.start_ea,
            self.region_size,
            self.region_desc,
            self.has_selection,
        ) = patch_region(ctx)
        self.trace_id = make_trace_id("asm", self.start_ea)

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("Assemble")
        self.dialog.resize(1080, 460)

        self.original_entries = get_original_entries(ctx)
        self.original_text = "\n".join(entry["text"] for entry in self.original_entries if entry["text"])
        self.original_asm_text = join_entry_asm_lines(self.original_entries)
        self.original_bytes = b"".join(entry["bytes"] for entry in self.original_entries)

        self.preview_text = self.original_asm_text
        self.preview_bytes = self.original_bytes
        self.preview_infos = build_preview_infos_from_entries(self.original_entries)

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
        debug_log(
            "assemble_dialog.open",
            trace_id=self.trace_id,
            start_ea="0x%X" % self.start_ea,
            region_size=self.region_size,
            original_asm=self.original_asm_text,
            input_file=input_file_path(),
        )

    def _build_syntax_menu(self):
        """Create the quick reference dropdown menu."""
        _QtCore, _QtGui, QtWidgets = load_qt()
        menu = QtWidgets.QMenu(self.dialog)
        current_key = processor_key()
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
        _QtCore, _QtGui, QtWidgets = load_qt()
        menu = QtWidgets.QMenu(self.dialog)
        current_key = processor_key()
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
            self.preview_infos = build_preview_infos_from_entries(self.original_entries)
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
            debug_log(
                "assemble_dialog.preview.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                text=text,
            )
            self.preview_bytes, notes, self.preview_infos = assemble_multiline(
                self.start_ea, text, self.arch_key, self.original_entries
            )
            self.preview_text = text
            self.status.setText(
                "预览成功: %d bytes / 当前范围: %d bytes"
                % (len(self.preview_bytes), self.region_size)
            )
            debug_log(
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
            debug_log_exception(
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
            build_hint_text(
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
            debug_log(
                "assemble_dialog.apply.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                text=text,
                write_to_file=self.write_to_file.isChecked(),
            )
            patch_bytes, _notes, line_infos = assemble_multiline(
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
                patch_bytes += build_nop_bytes(
                    self.start_ea + len(patch_bytes),
                    self.region_size - len(patch_bytes),
                )

            transaction = begin_patch_transaction(
                "assemble",
                "修改汇编",
                self.start_ea,
                trace_id=self.trace_id,
                meta={
                    "region_size": self.region_size,
                    "write_to_file": self.write_to_file.isChecked(),
                },
            )
            record_transaction_operation(
                transaction,
                self.start_ea,
                patch_bytes,
                write_to_file=self.write_to_file.isChecked(),
                note="assemble_patch",
            )
            file_path = apply_code_patch(
                self.start_ea,
                patch_bytes,
                write_to_file=self.write_to_file.isChecked(),
            )
            applied_count = 1
            commit_patch_transaction(transaction)
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
            debug_log(
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
                rollback_partial_transaction(transaction, applied_count)
            except Exception as rollback_exc:
                debug_log_exception(
                    "assemble_dialog.partial_rollback.failure",
                    rollback_exc,
                    trace_id=self.trace_id,
                )
            debug_log_exception(
                "assemble_dialog.apply.failure",
                exc,
                trace_id=self.trace_id,
                text=text,
            )
            ida_kernwin.warning("修改汇编失败:\n%s" % exc)

    def exec(self):
        """Show the assemble dialog modelessly so IDA stays interactive."""
        return show_modeless_dialog(self)
