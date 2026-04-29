"""Main assemble dialog."""

import ida_kernwin

from ..asm.hints import build_hint_text
from ..asm.disasm import disassemble_bytes
from ..asm.operands import processor_key, sanitize_asm_line
from ..constants import PLUGIN_NAME
from ..ida_adapter import input_file_path
from ..logging_utils import debug_log, debug_log_exception, format_bytes_hex, make_trace_id
from ..patching.assemble_plan import preview_assembly_patch
from ..patching.bytes_patch import apply_code_patch, build_nop_bytes
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
    build_display_entry_for_ea,
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
from .patch_table import (
    COL_ASSEMBLY,
    COL_BYTES,
    create_patch_table,
    insert_patch_row,
    install_patch_table_key_filter,
    patch_table_assembly_text,
    patch_table_bytes_blob,
    patch_table_row_byte_count,
    patch_table_row_ea,
    remove_selected_patch_rows,
    set_patch_table_rows,
)
from .reference_dialogs import RegisterHelpDialog, SyntaxHelpDialog
from .trampoline_dialog import TrampolinePatchDialog


def _data_directive_failure_hint(text):
    """Return a user hint when assembly text looks like a string/data directive."""
    for line in (text or "").splitlines():
        stripped = line.strip().lower()
        if not stripped:
            continue
        if stripped.startswith(("db ", "db\t", "dw ", "dw\t", "dd ", "dd\t", "dq ", "dq\t")):
            return "\n\n如果你要修改字符串或 `db '...',0` 这类数据，请改用右键菜单“修改字符串”。"
    return ""


class AssemblePatchDialog:
    """Main assemble/preview/apply dialog opened from the popup menu."""

    def __init__(self, ctx):
        """Initialize dialog state from the current disassembly selection."""
        _QtCore, QtGui, QtWidgets = load_qt()
        self._QtCore = _QtCore
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
        self.dialog.setWindowTitle("Patching")
        self.dialog.resize(1180, 560)

        self.original_entries = get_original_entries(ctx)
        self.original_text = "\n".join(entry["text"] for entry in self.original_entries if entry["text"])
        self.original_asm_text = join_entry_asm_lines(self.original_entries)
        self.original_bytes = b"".join(entry["bytes"] for entry in self.original_entries)

        self.preview_text = self.original_asm_text
        self.preview_bytes = self.original_bytes
        self.preview_infos = build_preview_infos_from_entries(self.original_entries)
        self.preview_plan = None
        self.raw_bytes_dirty = False

        root = QtWidgets.QVBoxLayout(self.dialog)
        font = QtGui.QFont("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)

        self.splitter = QtWidgets.QSplitter(self.dialog)
        self.splitter.setOrientation(_QtCore.Qt.Horizontal)
        self.patch_table = create_patch_table(self.dialog, font)
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
        self.status = QtWidgets.QLabel("当前未输入汇编。", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.insert_row_btn = QtWidgets.QPushButton("插入行", self.dialog)
        self.insert_row_btn.clicked.connect(self._insert_row)
        toolbar.addWidget(self.insert_row_btn)

        self.delete_row_btn = QtWidgets.QPushButton("删除行", self.dialog)
        self.delete_row_btn.clicked.connect(self._delete_selected_rows)
        toolbar.addWidget(self.delete_row_btn)

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
        set_patch_table_rows(self.patch_table, self._build_table_rows(self.original_asm_text, self.original_bytes, self.preview_infos, None))
        self.status.setText("已载入当前指令。按 Enter/Space/Insert 插入下一行，点击“预览机器码”刷新。")
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

    def _current_text(self):
        """Return the current assembly text from the editable table."""
        return patch_table_assembly_text(self.patch_table)

    def _insert_row(self):
        """Append the next original item from IDA to the editable table."""
        row = self.patch_table.rowCount()
        if row > 0:
            prev = row - 1
            prev_ea = patch_table_row_ea(self.patch_table, prev)
            prev_size = patch_table_row_byte_count(self.patch_table, prev)
            next_ea = (prev_ea + max(prev_size, 1)) if prev_ea is not None else self.start_ea
        else:
            next_ea = self.start_ea
        entry = build_display_entry_for_ea(next_ea)
        self.original_entries.append(entry)
        insert_patch_row(
            self.patch_table,
            row=row,
            assembly=entry.get("asm") or "",
            address="0x%X" % int(entry.get("ea") or next_ea),
            bytes_value=format_bytes_hex(entry.get("bytes") or b""),
            ea=int(entry.get("ea") or next_ea),
        )
        debug_log(
            "assemble_dialog.insert_row",
            trace_id=self.trace_id,
            row=row,
            ea="0x%X" % int(entry.get("ea") or next_ea),
            bytes=format_bytes_hex(entry.get("bytes") or b""),
            asm=entry.get("asm") or "",
        )
        self.raw_bytes_dirty = False
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
        self.raw_bytes_dirty = False
        self._mark_preview_stale(refresh_context=False, refresh_hint=False)

    def _toggle_hint_panel(self):
        """Collapse or restore the right-side hint panel."""
        visible = self.hint_panel.isVisible()
        self.hint_panel.setVisible(not visible)
        self.toggle_hint_btn.setText("显示提示" if visible else "隐藏提示")

    def _on_table_item_changed(self, item):
        """Mark preview stale after an editable cell is committed."""
        if item is None or item.column() not in (COL_ASSEMBLY, COL_BYTES):
            return
        self.raw_bytes_dirty = item.column() == COL_BYTES
        self._mark_preview_stale(refresh_context=False, refresh_hint=False)

    def _mark_preview_stale(self, refresh_context=True, refresh_hint=True):
        """Reset preview state when table assembly changes."""
        current_text = self._current_text().strip()
        if self.raw_bytes_dirty:
            self.preview_bytes = None
            self.preview_infos = None
            self.preview_plan = None
        elif current_text == self.original_asm_text:
            self.preview_text = self.original_asm_text
            self.preview_bytes = self.original_bytes
            self.preview_infos = build_preview_infos_from_entries(self.original_entries)
            self.preview_plan = None
        elif current_text != self.preview_text:
            self.preview_bytes = None
            self.preview_infos = None
            self.preview_plan = None
        if self.raw_bytes_dirty:
            self.status.setText("Bytes 列已修改。点击“预览机器码”校验机器码；Enter 插入下一行。")
        elif current_text:
            self.status.setText("编辑中。点击“预览机器码”刷新机器码；Enter 插入下一行。")
        else:
            self.status.setText("当前未输入汇编。")
        if refresh_context:
            self._refresh_context_panel()
        elif refresh_hint:
            self._refresh_hint_panel()

    def _preview_machine_code(self, live=False):
        """Assemble current table text and refresh preview/status output."""
        if self.raw_bytes_dirty:
            self._preview_raw_bytes(live=live)
            return

        text = self._current_text().strip()
        if not text:
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
            self.status.setText(
                "%s失败: %s%s"
                % ("自动预览" if live else "预览", exc, _data_directive_failure_hint(text))
            )
            debug_log_exception(
                "assemble_dialog.preview.failure",
                exc,
                trace_id=self.trace_id,
                text=text,
                live=live,
            )
        self._refresh_context_panel()

    def _build_raw_bytes_plan(self, raw_bytes):
        """Build a direct machine-code patch plan from the Bytes column."""
        if not raw_bytes:
            raise RuntimeError("Bytes 列没有可写入的机器码。")

        requested_region_size = int(self.region_size)
        effective_region_size = requested_region_size
        if len(raw_bytes) > requested_region_size:
            if self.has_selection:
                raise RuntimeError(
                    "机器码长度 %d bytes 超出当前选中范围 %d bytes。"
                    % (len(raw_bytes), requested_region_size)
                )
            effective_region_size = len(raw_bytes)

        tail_nop_bytes = b""
        if len(raw_bytes) < effective_region_size:
            tail_nop_bytes = build_nop_bytes(
                self.start_ea + len(raw_bytes),
                effective_region_size - len(raw_bytes),
            )

        patch_bytes = raw_bytes + tail_nop_bytes
        return {
            "start_ea": self.start_ea,
            "requested_region_size": requested_region_size,
            "effective_region_size": effective_region_size,
            "requested_end_ea": self.start_ea + requested_region_size,
            "effective_end_ea": self.start_ea + effective_region_size,
            "assembled_bytes": raw_bytes,
            "patch_bytes": patch_bytes,
            "tail_nop_bytes": tail_nop_bytes,
            "notes": ["raw-bytes"],
            "line_infos": None,
            "overflow_size": max(0, len(raw_bytes) - requested_region_size),
            "overflow_end_ea": self.start_ea + len(raw_bytes),
            "exceeds_selection": bool(self.has_selection and len(raw_bytes) > requested_region_size),
            "expanded_to_instruction_boundary": False,
            "expansion": None,
            "requires_confirmation": False,
        }

    def _preview_raw_bytes(self, live=False):
        """Validate Bytes-column edits without assembling the Assembly column."""
        try:
            raw_bytes = patch_table_bytes_blob(self.patch_table)
            plan = self._build_raw_bytes_plan(raw_bytes)
            raw_infos = disassemble_bytes(self.start_ea, raw_bytes, self.arch_key)
            raw_text = "\n".join(info["line"] for info in raw_infos) if raw_infos else self._current_text().strip()
            self.preview_text = raw_text
            self.preview_bytes = raw_bytes
            self.preview_infos = raw_infos or None
            self.preview_plan = plan
            if raw_infos:
                self.status.setText(
                    "%s成功: raw %d bytes，已反汇编到 Assembly，实际写入 %d bytes。"
                    % ("自动预览" if live else "预览", len(raw_bytes), len(plan["patch_bytes"]))
                )
                set_patch_table_rows(
                    self.patch_table,
                    self._build_table_rows(raw_text, raw_bytes, raw_infos, plan),
                )
            else:
                self.status.setText(
                    "%s成功: raw %d bytes，实际写入 %d bytes。未找到 Capstone，Assembly 不自动反汇编。"
                    % ("自动预览" if live else "预览", len(raw_bytes), len(plan["patch_bytes"]))
                )
            debug_log(
                "assemble_dialog.raw_preview.success",
                trace_id=self.trace_id,
                byte_count=len(raw_bytes),
                patch_size=len(plan["patch_bytes"]),
                disassembled=bool(raw_infos),
                live=live,
            )
        except Exception as exc:
            self.preview_bytes = None
            self.preview_infos = None
            self.preview_plan = None
            self.status.setText("%s失败: %s" % ("自动预览" if live else "预览", exc))
            debug_log_exception(
                "assemble_dialog.raw_preview.failure",
                exc,
                trace_id=self.trace_id,
                live=live,
            )
        self._refresh_hint_panel(self.preview_text, self.preview_bytes, self.preview_infos, self.preview_plan)

    def _current_preview_state(self):
        """Return current text and still-valid preview fields."""
        text = self._current_text().strip()
        if self.raw_bytes_dirty:
            return text, self.preview_bytes, self.preview_infos, self.preview_plan
        preview_bytes = self.preview_bytes if text and text == self.preview_text else None
        preview_infos = self.preview_infos if text and text == self.preview_text else None
        preview_plan = self.preview_plan if text and text == self.preview_text else None
        return text, preview_bytes, preview_infos, preview_plan

    def _build_table_rows(self, text, preview_bytes, preview_infos, preview_plan):
        """Build address/bytes/assembly rows for the patch table."""
        current_lines = [sanitize_asm_line(line) for line in text.splitlines()]
        current_lines = [line for line in current_lines if line]
        preview_infos = preview_infos or []
        row_count = max(len(current_lines), len(preview_infos), 1)
        rows = []
        current_ea = self.start_ea

        for index in range(row_count):
            original_entry = self.original_entries[index] if index < len(self.original_entries) else None
            current_line = current_lines[index] if index < len(current_lines) else ""
            preview_info = preview_infos[index] if index < len(preview_infos) else None
            if original_entry:
                address = int(original_entry.get("ea") or current_ea)
            else:
                address = current_ea

            asm_text = current_line or (original_entry.get("asm") if original_entry else "")
            if not asm_text and original_entry:
                asm_text = original_entry.get("text") or ""
            row_bytes = (
                preview_info.get("bytes")
                if preview_info and preview_bytes is not None
                else (original_entry.get("bytes") if original_entry else b"")
            )
            rows.append(
                {
                    "ea": address,
                    "address": "0x%X" % address,
                    "bytes": format_bytes_hex(row_bytes),
                    "assembly": asm_text or "",
                    "highlight": index == 0 or address == self.start_ea,
                }
            )

            if preview_info and preview_info.get("bytes"):
                current_ea = address + len(preview_info.get("bytes") or b"")
            elif original_entry and original_entry.get("bytes"):
                current_ea = address + len(original_entry.get("bytes") or b"")

        return rows

    def _refresh_context_panel(self):
        """Refresh the patch table and right-side hint panel from current state."""
        text, preview_bytes, preview_infos, preview_plan = self._current_preview_state()
        set_patch_table_rows(
            self.patch_table,
            self._build_table_rows(text, preview_bytes, preview_infos, preview_plan),
        )
        self._refresh_hint_panel(text, preview_bytes, preview_infos, preview_plan)

    def _refresh_hint_panel(self, text=None, preview_bytes=None, preview_infos=None, preview_plan=None):
        """Refresh only the right-side hint panel."""
        if text is None:
            text, preview_bytes, preview_infos, preview_plan = self._current_preview_state()
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

    def _apply_raw_bytes_patch(self):
        """Write direct machine-code edits from the Bytes column."""
        transaction = None
        applied_count = 0
        try:
            raw_bytes = patch_table_bytes_blob(self.patch_table)
            plan = self._build_raw_bytes_plan(raw_bytes)
            debug_log(
                "assemble_dialog.raw_apply.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                raw_hex=format_bytes_hex(raw_bytes),
                write_to_file=self.write_to_file.isChecked(),
            )
            transaction = begin_patch_transaction(
                "raw_bytes",
                "修改机器码",
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
                note="raw_bytes_patch",
            )
            file_path = apply_code_patch(
                self.start_ea,
                plan["patch_bytes"],
                write_to_file=self.write_to_file.isChecked(),
            )
            applied_count = 1
            commit_patch_transaction(transaction)
            self.preview_text = self._current_text().strip()
            self.preview_bytes = raw_bytes
            self.preview_infos = None
            self.preview_plan = plan
            if self.write_to_file.isChecked():
                ida_kernwin.msg(
                    "[%s] 已写入 raw %d bytes 到 0x%X，并同步到输入文件: %s。\n"
                    % (PLUGIN_NAME, len(plan["patch_bytes"]), self.start_ea, file_path)
                )
            else:
                ida_kernwin.msg(
                    "[%s] 已写入 raw %d bytes 到 0x%X。\n"
                    % (PLUGIN_NAME, len(plan["patch_bytes"]), self.start_ea)
                )
            debug_log(
                "assemble_dialog.raw_apply.success",
                trace_id=self.trace_id,
                byte_count=len(plan["patch_bytes"]),
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
                    "assemble_dialog.raw_partial_rollback.failure",
                    rollback_exc,
                    trace_id=self.trace_id,
                )
            debug_log_exception(
                "assemble_dialog.raw_apply.failure",
                exc,
                trace_id=self.trace_id,
            )
            ida_kernwin.warning("修改机器码失败:\n%s" % exc)

    def _apply_patch(self):
        """Assemble current text and write the resulting bytes into IDA."""
        if self.raw_bytes_dirty:
            self._apply_raw_bytes_patch()
            return

        text = self._current_text().strip()
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
                    return
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
            ida_kernwin.warning("修改汇编失败:\n%s%s" % (exc, _data_directive_failure_hint(text)))

    def exec(self):
        """Show the assemble dialog modelessly so IDA stays interactive."""
        return show_modeless_dialog(self)
