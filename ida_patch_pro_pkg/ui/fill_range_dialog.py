"""Fill Range dialog."""

import ida_kernwin

from ..asm.operands import processor_key
from ..constants import PLUGIN_NAME
from ..ida_adapter import input_file_path, resolve_ea_text
from ..logging_utils import debug_log, debug_log_exception, format_bytes_hex, make_trace_id
from ..patching.fill import apply_fill_range_plan, preview_fill_range
from ..patching.selection import patch_region
from .common import load_qt, show_modeless_dialog


class FillRangeDialog:
    """Preview/apply repeated assembly fill over an arbitrary range."""

    def __init__(self, ctx):
        """Build the Fill Range dialog from the current selection context."""
        _QtCore, QtGui, QtWidgets = load_qt()
        self.ctx = ctx
        self.arch_key = processor_key()
        self.start_ea, region_size, region_desc, _has_selection = patch_region(ctx)
        self.end_ea = self.start_ea + region_size
        self.region_desc = region_desc
        self.trace_id = make_trace_id("fill", self.start_ea)
        self.preview_plan = None

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("Fill Range")
        self.dialog.resize(1100, 520)

        root = QtWidgets.QVBoxLayout(self.dialog)
        note = QtWidgets.QLabel(
            "说明: Fill Range 会从起始地址开始重复汇编你输入的指令，直到填满整个半开区间 `[start, end)`。"
            " 如果最后剩余空间不足一份完整指令，可选择自动补 NOP。",
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        current = QtWidgets.QLabel(
            "默认范围: %s | 当前输入文件: %s" % (self.region_desc, input_file_path() or "(none)"),
            self.dialog,
        )
        current.setWordWrap(True)
        root.addWidget(current)

        range_row = QtWidgets.QHBoxLayout()
        range_row.addWidget(QtWidgets.QLabel("起始地址", self.dialog))
        self.start_edit = QtWidgets.QLineEdit("0x%X" % self.start_ea, self.dialog)
        range_row.addWidget(self.start_edit, 1)
        range_row.addWidget(QtWidgets.QLabel("结束地址(不含)", self.dialog))
        self.end_edit = QtWidgets.QLineEdit("0x%X" % self.end_ea, self.dialog)
        range_row.addWidget(self.end_edit, 1)
        root.addLayout(range_row)

        body = QtWidgets.QHBoxLayout()
        self.editor = QtWidgets.QPlainTextEdit(self.dialog)
        self.editor.setPlaceholderText("例如:\nnop")
        font = QtGui.QFont("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)
        self.editor.setFont(font)
        self.editor.setPlainText("nop")
        body.addWidget(self.editor, 3)

        self.detail = QtWidgets.QPlainTextEdit(self.dialog)
        self.detail.setReadOnly(True)
        self.detail.setFont(font)
        body.addWidget(self.detail, 2)
        root.addLayout(body)

        toolbar = QtWidgets.QHBoxLayout()
        self.status = QtWidgets.QLabel("当前尚未预览 Fill Range。", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.tail_nop = QtWidgets.QCheckBox("尾部不足一份时自动补 NOP", self.dialog)
        self.tail_nop.setChecked(True)
        self.tail_nop.stateChanged.connect(self._invalidate_preview)
        toolbar.addWidget(self.tail_nop)

        self.write_to_file = QtWidgets.QCheckBox("同时写入输入文件", self.dialog)
        self.write_to_file.setToolTip("勾选后会把 Fill Range 结果同步写回输入文件。")
        toolbar.addWidget(self.write_to_file)

        self.preview_btn = QtWidgets.QPushButton("预览 Fill Range", self.dialog)
        self.preview_btn.clicked.connect(self._preview_fill)
        toolbar.addWidget(self.preview_btn)
        root.addLayout(toolbar)

        buttons = QtWidgets.QDialogButtonBox(self.dialog)
        self.apply_btn = buttons.addButton("应用", QtWidgets.QDialogButtonBox.AcceptRole)
        self.cancel_btn = buttons.addButton("取消", QtWidgets.QDialogButtonBox.RejectRole)
        self.apply_btn.clicked.connect(self._apply_fill)
        self.cancel_btn.clicked.connect(self.dialog.reject)
        root.addWidget(buttons)

        self.start_edit.textChanged.connect(self._invalidate_preview)
        self.end_edit.textChanged.connect(self._invalidate_preview)
        self.editor.textChanged.connect(self._invalidate_preview)
        self._refresh_detail()
        debug_log(
            "fill_range_dialog.open",
            trace_id=self.trace_id,
            start_ea="0x%X" % self.start_ea,
            end_ea="0x%X" % self.end_ea,
            input_file=input_file_path(),
        )

    def _invalidate_preview(self):
        """Drop stale preview data when any input changes."""
        self.preview_plan = None
        self.status.setText("编辑中。点击“预览 Fill Range”或直接“应用”。")
        self._refresh_detail()

    def _parsed_range(self):
        """Parse the current start/end address fields."""
        start_ea = resolve_ea_text(self.start_edit.text())
        end_ea = resolve_ea_text(self.end_edit.text())
        if start_ea is None or end_ea is None:
            raise RuntimeError("起始/结束地址无法解析，请输入有效的地址或符号。")
        if end_ea <= start_ea:
            raise RuntimeError("结束地址必须大于起始地址。")
        return start_ea, end_ea

    def _current_text(self):
        """Return the current fill pattern text."""
        return self.editor.toPlainText().strip()

    def _build_detail_text(self):
        """Build the right-side Fill Range summary."""
        try:
            start_ea, end_ea = self._parsed_range()
            range_text = "范围: 0x%X - 0x%X (共 %d bytes)" % (start_ea, end_ea, end_ea - start_ea)
        except Exception as exc:
            range_text = "范围: %s" % exc

        lines = [
            range_text,
            "架构: %s" % self.arch_key,
            "模式: %s" % ("尾部自动补 NOP" if self.tail_nop.isChecked() else "要求完整填满"),
            "",
            "当前模式文本:",
        ]
        if self._current_text():
            for line in self._current_text().splitlines():
                if line.strip():
                    lines.append("- %s" % line.strip())
        else:
            lines.append("- (empty)")

        if self.preview_plan is not None:
            lines.extend(
                [
                    "",
                    "预览结果:",
                    "- 重复次数: %d" % self.preview_plan["copy_count"],
                    "- 总写入大小: %d bytes" % len(self.preview_plan["patch_bytes"]),
                    "- 尾部 NOP: %d bytes" % len(self.preview_plan["tail_nop_bytes"]),
                ]
            )
            for index, copy in enumerate(self.preview_plan["copies"][:6], 1):
                lines.append(
                    "- #%d @ 0x%X: %s"
                    % (index, copy["start_ea"], format_bytes_hex(copy["bytes"]))
                )
            if len(self.preview_plan["copies"]) > 6:
                lines.append("- ...")
            if self.preview_plan["notes"]:
                lines.append("")
                lines.append("兼容说明:")
                for note in self.preview_plan["notes"]:
                    lines.append("- %s" % note)
        else:
            lines.extend(["", "预览结果:", "- 当前尚未生成 Fill Range 预览"])
        return "\n".join(lines)

    def _refresh_detail(self):
        """Refresh the summary panel."""
        self.detail.setPlainText(self._build_detail_text())

    def _compute_plan(self):
        """Compute the current Fill Range preview plan."""
        start_ea, end_ea = self._parsed_range()
        return preview_fill_range(
            start_ea,
            end_ea,
            self._current_text(),
            self.arch_key,
            tail_mode="nop" if self.tail_nop.isChecked() else "strict",
        )

    def _preview_fill(self):
        """Preview the current Fill Range request."""
        try:
            debug_log(
                "fill_range_dialog.preview.start",
                trace_id=self.trace_id,
                start_text=self.start_edit.text(),
                end_text=self.end_edit.text(),
                pattern_text=self._current_text(),
            )
            self.preview_plan = self._compute_plan()
            self.status.setText(
                "预览成功: 重复 %d 次 | 总写入 %d bytes"
                % (
                    self.preview_plan["copy_count"],
                    len(self.preview_plan["patch_bytes"]),
                )
            )
            debug_log(
                "fill_range_dialog.preview.success",
                trace_id=self.trace_id,
                copy_count=self.preview_plan["copy_count"],
                patch_size=len(self.preview_plan["patch_bytes"]),
                tail_size=len(self.preview_plan["tail_nop_bytes"]),
            )
        except Exception as exc:
            self.preview_plan = None
            self.status.setText("预览失败: %s" % exc)
            debug_log_exception(
                "fill_range_dialog.preview.failure",
                exc,
                trace_id=self.trace_id,
                start_text=self.start_edit.text(),
                end_text=self.end_edit.text(),
                pattern_text=self._current_text(),
            )
        self._refresh_detail()

    def _apply_fill(self):
        """Apply the current Fill Range request."""
        try:
            debug_log(
                "fill_range_dialog.apply.start",
                trace_id=self.trace_id,
                start_text=self.start_edit.text(),
                end_text=self.end_edit.text(),
                pattern_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
            )
            plan = self._compute_plan()
            file_path = apply_fill_range_plan(
                plan,
                write_to_file=self.write_to_file.isChecked(),
                trace_id=self.trace_id,
            )
            if self.write_to_file.isChecked():
                ida_kernwin.msg(
                    "[%s] Fill Range 完成: 0x%X - 0x%X，共 %d bytes，并同步到输入文件: %s。\n"
                    % (PLUGIN_NAME, plan["start_ea"], plan["end_ea"], len(plan["patch_bytes"]), file_path)
                )
            else:
                ida_kernwin.msg(
                    "[%s] Fill Range 完成: 0x%X - 0x%X，共 %d bytes。\n"
                    % (PLUGIN_NAME, plan["start_ea"], plan["end_ea"], len(plan["patch_bytes"]))
                )
            debug_log(
                "fill_range_dialog.apply.success",
                trace_id=self.trace_id,
                start_ea="0x%X" % plan["start_ea"],
                end_ea="0x%X" % plan["end_ea"],
                patch_size=len(plan["patch_bytes"]),
                file_path=file_path,
                write_to_file=self.write_to_file.isChecked(),
            )
            self.preview_plan = plan
            self.dialog.accept()
        except Exception as exc:
            self.status.setText("应用失败: %s" % exc)
            debug_log_exception(
                "fill_range_dialog.apply.failure",
                exc,
                trace_id=self.trace_id,
                start_text=self.start_edit.text(),
                end_text=self.end_edit.text(),
                pattern_text=self._current_text(),
                write_to_file=self.write_to_file.isChecked(),
            )
            ida_kernwin.warning("Fill Range 失败:\n%s" % exc)
            self._refresh_detail()

    def exec(self):
        """Show the Fill Range dialog modelessly."""
        return show_modeless_dialog(self)
