"""Trampoline/code-cave dialog."""

import ida_auto
import ida_kernwin
import idc

from ..asm.operands import processor_key, sanitize_asm_line
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
from ..trampoline.function_attach import attach_cave_to_owner_function
from ..trampoline.planner import preview_trampoline_plan
from .common import load_qt, show_modeless_dialog


class TrampolinePatchDialog:
    """Trampoline/code-cave dialog for CE-style jump patching."""

    def __init__(self, ctx):
        """Initialize the trampoline dialog from the current disassembly context."""
        _QtCore, QtGui, QtWidgets = load_qt()
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
        self.preview_text = ""

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
            % (PATCH_SEGMENT_NAME, PATCH_FILE_SECTION_NAME),
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        body = QtWidgets.QHBoxLayout()
        self.editor = QtWidgets.QPlainTextEdit(self.dialog)
        self.editor.setPlaceholderText(
            "例如:\n; 编辑代码洞主体。末尾回跳会自动追加。\ncall func1\nmov eax, 1234h\ncall func2"
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

        self.include_original = QtWidgets.QCheckBox("末尾自动补齐未保留的原指令并跳回", self.dialog)
        self.include_original.setChecked(False)
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
        root.addLayout(toolbar)

        buttons = QtWidgets.QDialogButtonBox(self.dialog)
        self.apply_btn = buttons.addButton("应用", QtWidgets.QDialogButtonBox.AcceptRole)
        self.cancel_btn = buttons.addButton("取消", QtWidgets.QDialogButtonBox.RejectRole)
        self.apply_btn.clicked.connect(self._apply_patch)
        self.cancel_btn.clicked.connect(self.dialog.reject)
        root.addWidget(buttons)

        self.editor.setPlainText(self.original_asm_text)
        self.status.setText("已载入当前所选汇编。可直接在编辑框中自由修改。")
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

    def _current_text(self):
        """Return the current editor text."""
        return self.editor.toPlainText().strip()

    def _load_original_into_editor(self):
        """Reload the currently selected original instructions into the editor."""
        self.include_original.setChecked(False)
        self.editor.setPlainText(self.original_asm_text)
        self.status.setText("已重新载入当前所选汇编。可直接修改顺序和内容。")

    def _build_editor_example_lines(self):
        """Build a CE-style multiline example for the right-side hint panel."""
        selected = []
        for entry in self.original_entries[:2]:
            line = sanitize_asm_line(entry.get("text") or entry.get("asm") or "")
            if line:
                selected.append(line)

        lines = [
            "例子:",
            "编辑框就相当于 CE 里的 `newmem:` 主体。",
            "末尾跳回会自动追加，不需要自己写 `jmp returnhere`。",
            "",
        ]
        if len(selected) >= 2:
            lines.extend(
                [
                    "当前选中:",
                    selected[0],
                    selected[1],
                    "",
                    "你可以直接改成:",
                    "mov eax, 1",
                    selected[0],
                    "mov eax, 2",
                    selected[1],
                ]
            )
        elif selected:
            lines.extend(
                [
                    "当前选中:",
                    selected[0],
                    "",
                    "你可以直接改成:",
                    "mov eax, 1",
                    selected[0],
                ]
            )
        else:
            lines.extend(["你可以直接写成:", "mov eax, 1", "call my_hook"])
        return lines

    def _on_text_changed(self):
        """Drop stale preview state when editor options change."""
        self.preview_plan = None
        self.preview_text = ""
        if self._current_text() or self.include_original.isChecked():
            if self._current_text() == self.original_asm_text and not self.include_original.isChecked():
                self.status.setText("已载入当前所选汇编。可直接在编辑框中自由修改。")
            else:
                self.status.setText("编辑中。点击“预览代码注入”或直接“应用”。")
        else:
            self.status.setText("当前代码洞内容为空。")
        self._refresh_context_panel()

    def _build_hint_text(self):
        """Build the right-side summary for the trampoline patch."""
        lines = ["覆盖原始指令:"]
        for index, entry in enumerate(self.original_entries, 1):
            lines.append("%d. 0x%X: %s" % (index, entry["ea"], entry["text"] or "(unknown)"))

        lines.append("")
        lines.append("入口补丁:")
        lines.append("- 原地址将写入 `jmp code_cave`，其余字节自动补 NOP")
        lines.append("- 返回地址: 0x%X" % (self.start_ea + self.region_size))
        lines.append(
            "- 当前模式: %s"
            % ("末尾自动补齐未保留的原指令" if self.include_original.isChecked() else "仅按编辑框中的完整顺序执行")
        )
        lines.append(
            "- 存储位置: %s"
            % ("输入文件内 `%s` 节" % PATCH_FILE_SECTION_NAME if self.write_to_file.isChecked() else "仅 IDB 内 .patch 段")
        )

        lines.append("")
        lines.append("编辑方式:")
        lines.append("- 编辑框默认已载入当前所选原始汇编")
        lines.append("- 你可以直接插入、删除、重排、改写这些指令")
        lines.append("- 结尾回跳 `jmp returnhere` 会自动追加，不需要自己写")

        custom_text = self._current_text()
        if custom_text:
            lines.append("")
            lines.append("当前代码洞主体:")
            for line in custom_text.splitlines():
                stripped = sanitize_asm_line(line)
                if stripped:
                    lines.append("- %s" % stripped)
        else:
            lines.append("")
            lines.append("当前代码洞主体:")
            lines.append("- (empty)")

        if self.preview_plan is not None and self.preview_text == custom_text:
            lines.append("")
            lines.append("预览结果:")
            lines.append("- 代码洞段: %s" % (self.preview_plan.get("segment_name") or ""))
            lines.append("- 代码洞起始: 0x%X" % self.preview_plan["cave_start"])
            if self.preview_plan.get("storage_mode") == "file_section":
                lines.append("- 代码洞来源: 输入文件里的专用补丁节 `%s`" % PATCH_FILE_SECTION_NAME)
            else:
                lines.append("- 代码洞来源: IDB 专用 .patch 段")
            lines.append("- 入口机器码: %s" % " ".join("%02X" % b for b in self.preview_plan["entry_bytes"]))
            lines.append("- 代码洞总长度: %d bytes" % len(self.preview_plan["cave_bytes"]))
            if self.preview_plan["risk_notes"]:
                lines.append("")
                lines.append("风险提示:")
                for note in self.preview_plan["risk_notes"]:
                    lines.append("- %s" % note)
        else:
            lines.append("")
            lines.append("预览结果:")
            lines.append("- 当前尚未生成新的代码洞预览")

        lines.append("")
        lines.append("注意:")
        lines.append("- 不写入输入文件时，默认在 IDB 内新增/复用 `%s` 段" % PATCH_SEGMENT_NAME)
        lines.append("- 写入输入文件时，默认创建/扩展 `%s` 节；不再依赖现成 code cave" % PATCH_FILE_SECTION_NAME)
        lines.append("- 高级用法仍可选 `{{orig}}` / `{{orig:N}}`，但默认不需要")
        lines.append("- 代码洞更接近 CE 的 `newmem` 主体：只写你想执行的完整顺序即可")
        lines.append("- 若启用末尾自动补齐原指令，控制流/RIP 相对寻址仍需人工确认")
        lines.append("")
        lines.extend(self._build_editor_example_lines())
        return "\n".join(lines)

    def _refresh_context_panel(self):
        """Refresh the trampoline summary panel."""
        self.hint_panel.setPlainText(self._build_hint_text())

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

    def _preview_patch(self):
        """Preview cave allocation and trampoline bytes."""
        try:
            debug_log(
                "trampoline_dialog.preview.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.start_ea,
                include_original=self.include_original.isChecked(),
                custom_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
            )
            self.preview_plan = self._compute_plan()
            self.preview_text = self._current_text()
            self.status.setText(
                "预览成功: 入口 %d bytes | 代码洞 %d bytes"
                % (len(self.preview_plan["entry_bytes"]), len(self.preview_plan["cave_bytes"]))
            )
            debug_log(
                "trampoline_dialog.preview.success",
                trace_id=self.trace_id,
                cave_start="0x%X" % self.preview_plan["cave_start"],
                cave_size=len(self.preview_plan["cave_bytes"]),
                entry_size=len(self.preview_plan["entry_bytes"]),
                write_to_file=self.write_to_file.isChecked(),
            )
        except Exception as exc:
            self.preview_plan = None
            self.preview_text = ""
            self.status.setText("预览失败: %s" % exc)
            debug_log_exception(
                "trampoline_dialog.preview.failure",
                exc,
                trace_id=self.trace_id,
                include_original=self.include_original.isChecked(),
                custom_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
            )
        self._refresh_context_panel()

    def _apply_patch(self):
        """Write the trampoline entry and cave code to the database."""
        transaction = None
        applied_count = 0
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
            self.preview_text = self._current_text()
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
