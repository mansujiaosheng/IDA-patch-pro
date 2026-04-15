"""Main assemble dialog."""

import ida_kernwin

from ..asm.hints import build_hint_text
from ..asm.operands import processor_key
from ..constants import PLUGIN_NAME
from ..ida_adapter import input_file_path
from ..logging_utils import debug_log, debug_log_exception, make_trace_id
from ..patching.assemble_plan import preview_assembly_patch
from ..patching.bytes_patch import apply_code_patch
from ..patching.overflow_policy import (
    ASSEMBLE_OVERSIZE_ASK,
    ASSEMBLE_OVERSIZE_INLINE,
    ASSEMBLE_OVERSIZE_TRAMPOLINE,
    load_oversize_policy,
    save_oversize_policy,
)
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
from .oversize_prompt import prompt_oversize_patch_choice
from .reference_dialogs import RegisterHelpDialog, SyntaxHelpDialog
from .trampoline_dialog import TrampolinePatchDialog


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
        self.preview_plan = None

        root = QtWidgets.QVBoxLayout(self.dialog)
        target = QtWidgets.QLabel(
            "目标: %s | 可覆盖大小: %d bytes" % (self.region_desc, self.region_size),
            self.dialog,
        )
        root.addWidget(target)

        note = QtWidgets.QLabel(
            "说明: 输入一条或多条汇编。若结果小于目标范围，剩余字节会自动填充为 NOP。"
            " 若结果超过原范围，可按顶部“超长时”策略决定是继续覆盖还是改用代码注入。",
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

        self.live_preview = QtWidgets.QCheckBox("实时预览", self.dialog)
        self.live_preview.setChecked(True)
        self.live_preview.setToolTip("勾选后会在停止输入片刻后自动刷新机器码预览。")
        self.live_preview.stateChanged.connect(self._on_live_preview_toggled)
        toolbar.addWidget(self.live_preview)

        self.preview_btn = QtWidgets.QPushButton("预览机器码", self.dialog)
        self.preview_btn.clicked.connect(lambda: self._preview_machine_code(live=False))
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

        toolbar.addWidget(QtWidgets.QLabel("超长时", self.dialog))
        self.oversize_policy = QtWidgets.QComboBox(self.dialog)
        self.oversize_policy.addItem("每次询问", ASSEMBLE_OVERSIZE_ASK)
        self.oversize_policy.addItem("继续覆盖", ASSEMBLE_OVERSIZE_INLINE)
        self.oversize_policy.addItem("改用代码注入", ASSEMBLE_OVERSIZE_TRAMPOLINE)
        self.oversize_policy.setToolTip("当新汇编长度超过原范围时，决定是每次询问、直接继续覆盖，还是直接改用代码注入。")
        self._sync_oversize_policy_combo()
        self.oversize_policy.currentIndexChanged.connect(self._on_oversize_policy_changed)
        toolbar.addWidget(self.oversize_policy)
        root.addLayout(toolbar)

        buttons = QtWidgets.QDialogButtonBox(self.dialog)
        self.apply_btn = buttons.addButton("应用", QtWidgets.QDialogButtonBox.AcceptRole)
        self.cancel_btn = buttons.addButton("取消", QtWidgets.QDialogButtonBox.RejectRole)
        self.apply_btn.clicked.connect(self._apply_patch)
        self.cancel_btn.clicked.connect(self.dialog.reject)
        root.addWidget(buttons)
        self.editor.setPlainText(self.original_asm_text)
        self.status.setText("已载入当前指令。点击“预览机器码”或直接“应用”。")
        self.preview_timer = _QtCore.QTimer(self.dialog)
        self.preview_timer.setSingleShot(True)
        self.preview_timer.setInterval(320)
        self.preview_timer.timeout.connect(self._run_live_preview)
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
            self.preview_plan = None
        elif current_text != self.preview_text:
            self.preview_bytes = None
            self.preview_infos = None
            self.preview_plan = None
        if current_text:
            self.status.setText("编辑中。点击“预览机器码”或直接“应用”。")
        else:
            self.status.setText("当前未输入汇编。")
        self._queue_live_preview()
        self._refresh_context_panel()

    def _on_live_preview_toggled(self):
        """Enable or disable delayed preview updates."""
        if self.live_preview.isChecked():
            self._queue_live_preview()
        else:
            self.preview_timer.stop()

    def _queue_live_preview(self):
        """Schedule a delayed preview refresh when live preview is enabled."""
        current_text = self.editor.toPlainText().strip()
        if not self.live_preview.isChecked():
            self.preview_timer.stop()
            return
        if not current_text or current_text == self.original_asm_text:
            self.preview_timer.stop()
            return
        self.preview_timer.start()

    def _run_live_preview(self):
        """Trigger one delayed live preview refresh."""
        self._preview_machine_code(live=True)

    def _preview_machine_code(self, live=False):
        """Assemble current editor text and refresh preview/status output."""
        text = self.editor.toPlainText().strip()
        if not text:
            self.preview_timer.stop()
            self.status.setText("当前未输入汇编。")
            self.preview_text = ""
            self.preview_bytes = None
            self.preview_infos = None
            self.preview_plan = None
            self._refresh_context_panel()
            return

        try:
            debug_log(
                "assemble_dialog.preview.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                text=text,
                live=live,
            )
            self.preview_plan = preview_assembly_patch(
                self.start_ea,
                self.region_size,
                text,
                self.arch_key,
                self.original_entries,
                has_selection=self.has_selection,
                extend_to_instruction_boundary=not self.has_selection,
            )
            self.preview_bytes = self.preview_plan["assembled_bytes"]
            notes = self.preview_plan["notes"]
            self.preview_infos = self.preview_plan["line_infos"]
            self.preview_text = text
            if self.preview_plan["exceeds_selection"]:
                self.status.setText(
                    "预览成功: %d bytes，但已超过当前选中范围 %d bytes。"
                    % (len(self.preview_bytes), self.region_size)
                )
            elif self.preview_plan["expanded_to_instruction_boundary"]:
                self.status.setText(
                    "预览成功: 汇编 %d bytes，实际将按完整指令边界写入 %d bytes。"
                    % (
                        len(self.preview_plan["assembled_bytes"]),
                        self.preview_plan["effective_region_size"],
                    )
                )
            else:
                self.status.setText(
                    "预览成功: %d bytes / 当前范围: %d bytes"
                    % (len(self.preview_bytes), self.region_size)
                )
            debug_log(
                "assemble_dialog.preview.success",
                trace_id=self.trace_id,
                byte_count=len(self.preview_bytes),
                notes=" | ".join(notes),
                effective_region_size=self.preview_plan["effective_region_size"],
                expanded=self.preview_plan["expanded_to_instruction_boundary"],
                live=live,
            )
        except Exception as exc:
            self.preview_text = ""
            self.preview_bytes = None
            self.preview_infos = None
            self.preview_plan = None
            self.status.setText("%s失败: %s" % ("实时预览" if live else "预览", exc))
            debug_log_exception(
                "assemble_dialog.preview.failure",
                exc,
                trace_id=self.trace_id,
                text=text,
                live=live,
            )
        self._refresh_context_panel()

    def _refresh_context_panel(self):
        """Refresh the right-side hint panel from current editor/preview state."""
        text = self.editor.toPlainText().strip()
        preview_bytes = self.preview_bytes if text and text == self.preview_text else None
        preview_infos = self.preview_infos if text and text == self.preview_text else None
        preview_plan = self.preview_plan if text and text == self.preview_text else None
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
                preview_plan=preview_plan,
            )
        )

    def _sync_oversize_policy_combo(self):
        """Reflect the persisted oversize policy in the toolbar combo box."""
        saved = load_oversize_policy()
        for index in range(self.oversize_policy.count()):
            if self.oversize_policy.itemData(index) == saved:
                self.oversize_policy.setCurrentIndex(index)
                return

    def _on_oversize_policy_changed(self):
        """Persist toolbar changes for the oversized-assembly handling policy."""
        save_oversize_policy(self.oversize_policy.currentData())

    def _switch_to_trampoline(self, text):
        """Open the trampoline dialog and prefill it with the current oversized assembly."""
        TrampolinePatchDialog(
            self.ctx,
            initial_text=text,
            initial_include_original=False,
        ).exec()
        self.dialog.reject()

    def _resolve_oversize_action(self, plan):
        """Resolve what to do when the current inline patch is larger than the original range."""
        if int(plan.get("overflow_size") or 0) <= 0:
            return ASSEMBLE_OVERSIZE_INLINE

        saved_policy = load_oversize_policy()
        can_inline = not self.has_selection and not plan.get("exceeds_selection")
        if saved_policy == ASSEMBLE_OVERSIZE_INLINE and can_inline:
            return ASSEMBLE_OVERSIZE_INLINE
        if saved_policy == ASSEMBLE_OVERSIZE_TRAMPOLINE:
            return ASSEMBLE_OVERSIZE_TRAMPOLINE

        choice, remember = prompt_oversize_patch_choice(self.dialog, plan, self.has_selection)
        if remember and choice in (ASSEMBLE_OVERSIZE_INLINE, ASSEMBLE_OVERSIZE_TRAMPOLINE):
            save_oversize_policy(choice)
            self._sync_oversize_policy_combo()
        return choice

    def _apply_patch(self):
        """Assemble current text and write the resulting bytes into IDA."""
        text = self.editor.toPlainText().strip()
        transaction = None
        applied_count = 0
        try:
            self.preview_timer.stop()
            debug_log(
                "assemble_dialog.apply.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                text=text,
                write_to_file=self.write_to_file.isChecked(),
            )
            plan = preview_assembly_patch(
                self.start_ea,
                self.region_size,
                text,
                self.arch_key,
                self.original_entries,
                has_selection=self.has_selection,
                extend_to_instruction_boundary=not self.has_selection,
            )
            oversize_action = self._resolve_oversize_action(plan)
            if oversize_action == ASSEMBLE_OVERSIZE_TRAMPOLINE:
                self._switch_to_trampoline(text)
                return
            if oversize_action != ASSEMBLE_OVERSIZE_INLINE:
                if plan["exceeds_selection"]:
                    self.status.setText("已取消。当前选区不足，可改用代码注入或扩大选区后重试。")
                elif plan["overflow_size"] > 0:
                    self.status.setText("已取消。当前汇编超过原范围。")
                    return

            transaction = begin_patch_transaction(
                "assemble",
                "修改汇编",
                self.start_ea,
                trace_id=self.trace_id,
                meta={
                    "region_size": plan["effective_region_size"],
                    "write_to_file": self.write_to_file.isChecked(),
                },
            )
            record_transaction_operation(
                transaction,
                self.start_ea,
                plan["patch_bytes"],
                write_to_file=self.write_to_file.isChecked(),
                note="assemble_patch",
            )
            file_path = apply_code_patch(
                self.start_ea,
                plan["patch_bytes"],
                write_to_file=self.write_to_file.isChecked(),
            )
            applied_count = 1
            commit_patch_transaction(transaction)
            self.preview_text = text
            self.preview_bytes = plan["assembled_bytes"]
            self.preview_infos = plan["line_infos"]
            self.preview_plan = plan
            if self.write_to_file.isChecked():
                ida_kernwin.msg(
                    "[%s] 已写入 %d bytes 到 0x%X，并同步到输入文件: %s。\n"
                    % (PLUGIN_NAME, len(plan["patch_bytes"]), self.start_ea, file_path)
                )
            else:
                ida_kernwin.msg(
                    "[%s] 已写入 %d bytes 到 0x%X。\n"
                    % (PLUGIN_NAME, len(plan["patch_bytes"]), self.start_ea)
                )
            debug_log(
                "assemble_dialog.apply.success",
                trace_id=self.trace_id,
                byte_count=len(plan["patch_bytes"]),
                start_ea="0x%X" % self.start_ea,
                write_to_file=self.write_to_file.isChecked(),
                file_path=file_path,
                effective_region_size=plan["effective_region_size"],
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
