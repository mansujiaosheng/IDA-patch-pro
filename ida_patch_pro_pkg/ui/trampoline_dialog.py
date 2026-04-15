"""Trampoline/code-cave dialog."""

import ida_auto
import ida_kernwin
import idc

from ..asm.operands import processor_key
from ..backends.pe_backend import prepare_file_patch_segment
from ..constants import (
    PATCH_FILE_SECTION_NAME,
    PATCH_SEGMENT_NAME,
    PATCH_STUB_ALIGN,
    PLUGIN_NAME,
)
from ..ida_adapter import input_file_path
from ..logging_utils import debug_log, debug_log_exception, make_trace_id
from ..patching.bytes_patch import apply_code_patch, build_nop_bytes
from ..patching.rollback import rollback_partial_transaction
from ..patching.selection import get_entries_for_range, hook_region, join_entry_asm_lines
from ..patching.transactions import (
    begin_patch_transaction,
    commit_patch_transaction,
    record_transaction_operation,
)
from ..trampoline.caves import ensure_patch_segment, next_patch_cursor
from ..trampoline.hints import build_trampoline_hint_text
from ..trampoline.function_attach import attach_cave_to_owner_function
from ..trampoline.planner import preview_trampoline_plan
from .common import load_qt, show_modeless_dialog
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
        self.dialog.setWindowTitle("代码注入 / Trampoline")
        self.dialog.resize(1120, 540)

        root = QtWidgets.QVBoxLayout(self.dialog)
        target = QtWidgets.QLabel(
            "目标: %s | 覆盖大小: %d bytes" % (self.region_desc, self.region_size),
            self.dialog,
        )
        root.addWidget(target)

        note = QtWidgets.QLabel(
            "说明: 原地址会写入 `jmp` 跳板，再在代码洞里执行你的自定义代码。"
            " 不勾选“同时写入输入文件”时，代码洞只存在于 IDB 的 `%s` 段；"
            " 勾选后会自动创建/扩展输入文件中的 `%s` 节，适合实际运行和调试。"
            " 高级用法可在编辑框中使用 `{{orig}}` / `{{orig:N}}`。"
            % (PATCH_SEGMENT_NAME, PATCH_FILE_SECTION_NAME),
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        body = QtWidgets.QHBoxLayout()
        self.editor = QtWidgets.QPlainTextEdit(self.dialog)
        self.editor.setPlaceholderText(
            "例如:\ncall my_hook\n{{orig}}\n\n或:\npush rax\nmov eax, 1234h\npop rax"
        )
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
        self.status = QtWidgets.QLabel("当前未预览代码洞。", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.live_preview = QtWidgets.QCheckBox("实时预览", self.dialog)
        self.live_preview.setChecked(True)
        self.live_preview.setToolTip("勾选后会在停止输入片刻后自动刷新代码洞机器码预览。")
        self.live_preview.stateChanged.connect(self._on_live_preview_toggled)
        toolbar.addWidget(self.live_preview)

        self.include_original = QtWidgets.QCheckBox("末尾自动补齐未保留的原指令并跳回", self.dialog)
        self.include_original.setChecked(bool(initial_include_original))
        self.include_original.stateChanged.connect(self._on_text_changed)
        toolbar.addWidget(self.include_original)

        self.load_original_btn = QtWidgets.QPushButton("载入原指令", self.dialog)
        self.load_original_btn.clicked.connect(self._load_original_into_editor)
        toolbar.addWidget(self.load_original_btn)

        self.write_to_file = QtWidgets.QCheckBox("同时写入输入文件", self.dialog)
        self.write_to_file.setToolTip("勾选后会创建或扩展输入文件中的专用补丁节，并把入口/代码洞都写回输入文件。")
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
        root.addLayout(toolbar)

        buttons = QtWidgets.QDialogButtonBox(self.dialog)
        self.apply_btn = buttons.addButton("应用", QtWidgets.QDialogButtonBox.AcceptRole)
        self.cancel_btn = buttons.addButton("取消", QtWidgets.QDialogButtonBox.RejectRole)
        self.apply_btn.clicked.connect(self._apply_patch)
        self.cancel_btn.clicked.connect(self.dialog.reject)
        root.addWidget(buttons)

        self.editor.setPlainText(initial_text if initial_text is not None else self.original_asm_text)
        self.status.setText("已载入当前所选汇编。可直接在编辑框中自由修改。")
        self.preview_timer = _QtCore.QTimer(self.dialog)
        self.preview_timer.setSingleShot(True)
        self.preview_timer.setInterval(320)
        self.preview_timer.timeout.connect(self._run_live_preview)
        self.editor.textChanged.connect(self._on_text_changed)
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
        """Return the current editor text."""
        return self.editor.toPlainText().strip()

    def _current_signature(self):
        """Return the current preview-relevant input signature."""
        return (
            self._current_text(),
            bool(self.include_original.isChecked()),
            bool(self.write_to_file.isChecked()),
        )

    def _load_original_into_editor(self):
        """Reload the currently selected original instructions into the editor."""
        self.include_original.setChecked(False)
        self.editor.setPlainText(self.original_asm_text)
        self.status.setText("已重新载入当前所选汇编。可直接修改顺序和内容。")

    def _on_text_changed(self):
        """Drop stale preview state when editor options change."""
        self.preview_plan = None
        self.preview_signature = None
        if self._current_text() or self.include_original.isChecked():
            if self._current_text() == self.original_asm_text and not self.include_original.isChecked():
                self.status.setText("已载入当前所选汇编。可直接在编辑框中自由修改。")
            else:
                self.status.setText("编辑中。点击“预览代码注入”或直接“应用”。")
        else:
            self.status.setText("当前代码洞内容为空。")
        self._queue_live_preview()
        self._refresh_context_panel()

    def _on_live_preview_toggled(self):
        """Enable or disable delayed preview updates."""
        if self.live_preview.isChecked():
            self._queue_live_preview()
        else:
            self.preview_timer.stop()

    def _queue_live_preview(self):
        """Schedule a delayed live preview refresh when live preview is enabled."""
        if not self.live_preview.isChecked():
            self.preview_timer.stop()
            return
        if not self._current_text() and not self.include_original.isChecked():
            self.preview_timer.stop()
            return
        self.preview_timer.start()

    def _run_live_preview(self):
        """Trigger one delayed live preview refresh."""
        self._preview_patch(live=True)

    def _refresh_context_panel(self):
        """Refresh the trampoline summary panel."""
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
                    "实时预览" if live else "预览",
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
            self.status.setText("%s失败: %s" % ("实时预览" if live else "预览", exc))
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
        transaction = None
        applied_count = 0
        try:
            self.preview_timer.stop()
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

            cave_start = plan["cave_start"]
            cave_end = plan["cave_end"]
            file_path = ""
            if plan.get("storage_mode") == "idb":
                seg = ensure_patch_segment(len(plan["cave_bytes"]) + PATCH_STUB_ALIGN)
                new_cave_start = next_patch_cursor(seg)
                if new_cave_start != plan["cave_start"]:
                    plan = preview_trampoline_plan(
                        self.start_ea,
                        self.region_size,
                        self._current_text(),
                        self.original_entries,
                        self.include_original.isChecked(),
                        write_to_file=self.write_to_file.isChecked(),
                    )
                    cave_start = plan["cave_start"]
                    cave_end = plan["cave_end"]
            elif plan.get("storage_mode") == "file_section":
                required_total = (
                    (plan["cave_start"] - plan.get("alloc_base_ea", plan["cave_start"]))
                    + len(plan["cave_bytes"])
                    + PATCH_STUB_ALIGN
                )
                file_info = prepare_file_patch_segment(required_total, apply_changes=True)
                seg = file_info.get("segment")
                new_cave_start = next_patch_cursor(seg) if seg is not None else plan["cave_start"]
                if new_cave_start != plan["cave_start"]:
                    plan = preview_trampoline_plan(
                        self.start_ea,
                        self.region_size,
                        self._current_text(),
                        self.original_entries,
                        self.include_original.isChecked(),
                        write_to_file=self.write_to_file.isChecked(),
                    )
                    cave_start = plan["cave_start"]
                    cave_end = plan["cave_end"]

            transaction = begin_patch_transaction(
                "trampoline",
                "代码注入",
                self.start_ea,
                trace_id=self.trace_id,
                meta={
                    "start_ea": self.start_ea,
                    "region_size": self.region_size,
                    "write_to_file": self.write_to_file.isChecked(),
                    "cave_start": cave_start,
                    "cave_end": cave_end,
                    "owner_ea": self.start_ea,
                },
            )
            record_transaction_operation(
                transaction,
                cave_start,
                plan["cave_bytes"],
                write_to_file=self.write_to_file.isChecked(),
                note="trampoline_cave",
            )
            file_path = apply_code_patch(
                cave_start,
                plan["cave_bytes"],
                write_to_file=self.write_to_file.isChecked(),
            )
            applied_count = 1
            idc.set_name(cave_start, "patch_cave_%X" % self.start_ea, idc.SN_NOWARN)
            if not attach_cave_to_owner_function(self.start_ea, cave_start, cave_end):
                debug_log(
                    "trampoline.attach_tail.failure",
                    owner="0x%X" % self.start_ea,
                    cave_start="0x%X" % cave_start,
                    cave_end="0x%X" % cave_end,
                )

            entry_patch = plan["entry_bytes"]
            if len(entry_patch) < self.region_size:
                entry_patch += build_nop_bytes(self.start_ea + len(entry_patch), self.region_size - len(entry_patch))
            record_transaction_operation(
                transaction,
                self.start_ea,
                entry_patch,
                write_to_file=self.write_to_file.isChecked(),
                note="trampoline_entry",
            )
            apply_code_patch(
                self.start_ea,
                entry_patch,
                write_to_file=self.write_to_file.isChecked(),
            )
            applied_count = 2
            commit_patch_transaction(transaction)
            ida_auto.auto_wait()
            if not attach_cave_to_owner_function(self.start_ea, cave_start, cave_end):
                debug_log(
                    "trampoline.attach_tail.failure.post_entry",
                    owner="0x%X" % self.start_ea,
                    cave_start="0x%X" % cave_start,
                    cave_end="0x%X" % cave_end,
                )

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
            try:
                rollback_partial_transaction(transaction, applied_count)
            except Exception as rollback_exc:
                debug_log_exception(
                    "trampoline_dialog.partial_rollback.failure",
                    rollback_exc,
                    trace_id=self.trace_id,
                )
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
