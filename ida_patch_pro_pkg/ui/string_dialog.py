"""String patch dialog."""

import ida_bytes
import ida_kernwin

from ..constants import PLUGIN_NAME
from ..ida_adapter import input_file_path, resolve_ea_text
from ..logging_utils import debug_log, debug_log_exception, format_bytes_hex, make_trace_id
from ..patching.bytes_patch import apply_data_patch
from ..patching.rollback import rollback_partial_transaction
from ..patching.selection import patch_region
from ..patching.transactions import (
    begin_patch_transaction,
    commit_patch_transaction,
    record_transaction_operation,
)
from .common import load_qt, show_modeless_dialog

ENCODINGS = ("utf-8", "gbk", "ascii")
BYTE_PREVIEW_LIMIT = 160


def _read_bytes(ea, size):
    """Read bytes from IDB, returning an empty buffer on unmapped ranges."""
    if size <= 0:
        return b""
    buf = ida_bytes.get_bytes(ea, size)
    return bytes(buf) if buf else b""


def _first_c_string_bytes(buf):
    """Return bytes before the first NUL terminator."""
    index = buf.find(b"\x00")
    if index >= 0:
        return buf[:index]
    return buf


def _decode_current_text(buf):
    """Decode existing bytes for the initial editor text."""
    raw = _first_c_string_bytes(buf)
    if not raw:
        return ""
    for encoding in ("utf-8", "gbk", "ascii"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", errors="replace")


def _format_bytes_preview(buf, limit=BYTE_PREVIEW_LIMIT):
    """Format bytes, truncating long previews for the right-side panel."""
    if len(buf) <= limit:
        return format_bytes_hex(buf)
    return "%s ... (+%d bytes)" % (format_bytes_hex(buf[:limit]), len(buf) - limit)


class StringPatchDialog:
    """Patch user text as data bytes and optionally define it as a string."""

    def __init__(self, ctx):
        """Build the string patch dialog from the current selection context."""
        _QtCore, QtGui, QtWidgets = load_qt()
        self.ctx = ctx
        (
            self.start_ea,
            self.region_size,
            self.region_desc,
            self.has_selection,
        ) = patch_region(ctx)
        self.trace_id = make_trace_id("str", self.start_ea)
        self.preview_plan = None
        self.initial_read_size = min(max(int(self.region_size), 1), 4096)

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("修改字符串")
        self.dialog.resize(980, 520)

        root = QtWidgets.QVBoxLayout(self.dialog)

        target = QtWidgets.QLabel(
            "默认目标: %s | 当前输入文件: %s"
            % (self.region_desc, input_file_path() or "(none)"),
            self.dialog,
        )
        target.setWordWrap(True)
        root.addWidget(target)

        form = QtWidgets.QFormLayout()
        self.start_edit = QtWidgets.QLineEdit("0x%X" % self.start_ea, self.dialog)
        form.addRow("起始地址:", self.start_edit)

        range_row = QtWidgets.QHBoxLayout()
        self.limit_to_range = QtWidgets.QCheckBox("限制写入大小", self.dialog)
        self.limit_to_range.setChecked(self.has_selection)
        range_row.addWidget(self.limit_to_range)

        self.max_size = QtWidgets.QSpinBox(self.dialog)
        self.max_size.setMinimum(1)
        self.max_size.setMaximum(0x7FFFFFFF)
        self.max_size.setValue(max(int(self.region_size), 1))
        range_row.addWidget(self.max_size)
        range_row.addWidget(QtWidgets.QLabel("bytes", self.dialog))

        self.pad_zero = QtWidgets.QCheckBox("不足时补 00", self.dialog)
        self.pad_zero.setChecked(self.has_selection)
        range_row.addWidget(self.pad_zero)
        range_row.addStretch(1)
        form.addRow("范围:", range_row)
        root.addLayout(form)

        font = QtGui.QFont("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)

        self.splitter = QtWidgets.QSplitter(self.dialog)
        self.splitter.setOrientation(_QtCore.Qt.Horizontal)

        self.editor = QtWidgets.QPlainTextEdit(self.dialog)
        self.editor.setFont(font)
        self.editor.setPlaceholderText("输入要写入的字符串，例如: ni hao")
        self.editor.setPlainText(_decode_current_text(_read_bytes(self.start_ea, self.initial_read_size)))
        self.splitter.addWidget(self.editor)

        self.detail = QtWidgets.QPlainTextEdit(self.dialog)
        self.detail.setReadOnly(True)
        self.detail.setFont(font)
        self.splitter.addWidget(self.detail)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)
        root.addWidget(self.splitter, 1)

        toolbar = QtWidgets.QHBoxLayout()
        self.status = QtWidgets.QLabel("当前尚未预览字符串补丁。", self.dialog)
        toolbar.addWidget(self.status, 1)

        toolbar.addWidget(QtWidgets.QLabel("编码", self.dialog))
        self.encoding = QtWidgets.QComboBox(self.dialog)
        self.encoding.addItems(list(ENCODINGS))
        toolbar.addWidget(self.encoding)

        self.null_terminate = QtWidgets.QCheckBox("追加 \\0", self.dialog)
        self.null_terminate.setChecked(True)
        toolbar.addWidget(self.null_terminate)

        self.define_string = QtWidgets.QCheckBox("定义为字符串", self.dialog)
        self.define_string.setChecked(True)
        toolbar.addWidget(self.define_string)

        self.write_to_file = QtWidgets.QCheckBox("同时写入输入文件", self.dialog)
        toolbar.addWidget(self.write_to_file)

        self.preview_btn = QtWidgets.QPushButton("预览字符串", self.dialog)
        self.preview_btn.clicked.connect(self._preview_string)
        toolbar.addWidget(self.preview_btn)

        self.toggle_detail_btn = QtWidgets.QPushButton("隐藏提示", self.dialog)
        self.toggle_detail_btn.clicked.connect(self._toggle_detail_panel)
        toolbar.addWidget(self.toggle_detail_btn)
        root.addLayout(toolbar)

        buttons = QtWidgets.QDialogButtonBox(self.dialog)
        self.apply_btn = buttons.addButton("应用", QtWidgets.QDialogButtonBox.AcceptRole)
        self.cancel_btn = buttons.addButton("取消", QtWidgets.QDialogButtonBox.RejectRole)
        self.apply_btn.clicked.connect(self._apply_string)
        self.cancel_btn.clicked.connect(self.dialog.reject)
        root.addWidget(buttons)

        self.start_edit.textChanged.connect(self._invalidate_preview)
        self.limit_to_range.stateChanged.connect(self._on_limit_changed)
        self.max_size.valueChanged.connect(self._invalidate_preview)
        self.pad_zero.stateChanged.connect(self._invalidate_preview)
        self.editor.textChanged.connect(self._invalidate_preview)
        self.encoding.currentIndexChanged.connect(self._invalidate_preview)
        self.null_terminate.stateChanged.connect(self._invalidate_preview)
        self.define_string.stateChanged.connect(self._invalidate_preview)

        self._sync_range_controls()
        self._refresh_detail()
        debug_log(
            "string_dialog.open",
            trace_id=self.trace_id,
            start_ea="0x%X" % self.start_ea,
            region_size=self.region_size,
            has_selection=self.has_selection,
            input_file=input_file_path(),
        )

    def _sync_range_controls(self):
        """Enable range-only controls according to the range checkbox."""
        enabled = self.limit_to_range.isChecked()
        self.max_size.setEnabled(enabled)
        self.pad_zero.setEnabled(enabled)

    def _on_limit_changed(self, *_args):
        """React to range-limit changes."""
        self._sync_range_controls()
        self._invalidate_preview()

    def _invalidate_preview(self, *_args):
        """Drop stale preview data when inputs change."""
        self.preview_plan = None
        self.status.setText("编辑中。点击“预览字符串”或直接“应用”。")
        self._refresh_detail()

    def _parsed_start_ea(self):
        """Parse the editable start address."""
        ea = resolve_ea_text(self.start_edit.text())
        if ea is None:
            raise RuntimeError("起始地址无法解析，请输入有效地址或符号。")
        return ea

    def _encoded_text(self):
        """Encode editor text with the selected encoding."""
        encoding = self.encoding.currentText() or "utf-8"
        text = self.editor.toPlainText()
        try:
            raw_text = text.encode(encoding)
        except UnicodeEncodeError as exc:
            raise RuntimeError("当前文本无法用 %s 编码: %s" % (encoding, exc))
        return text, raw_text, encoding

    def _compute_plan(self):
        """Build the current string patch plan."""
        start_ea = self._parsed_start_ea()
        text, raw_text, encoding = self._encoded_text()
        patch_bytes = raw_text
        if self.null_terminate.isChecked():
            patch_bytes += b"\x00"

        limit_size = 0
        if self.limit_to_range.isChecked():
            limit_size = int(self.max_size.value())
            if len(patch_bytes) > limit_size:
                raise RuntimeError(
                    "字符串编码后为 %d bytes，超过当前限制 %d bytes。"
                    % (len(patch_bytes), limit_size)
                )
            if self.pad_zero.isChecked() and len(patch_bytes) < limit_size:
                patch_bytes += b"\x00" * (limit_size - len(patch_bytes))

        old_bytes = _read_bytes(start_ea, len(patch_bytes))
        return {
            "start_ea": start_ea,
            "text": text,
            "raw_text": raw_text,
            "encoding": encoding,
            "patch_bytes": patch_bytes,
            "old_bytes": old_bytes,
            "limit_size": limit_size,
            "null_terminate": self.null_terminate.isChecked(),
            "define_string": self.define_string.isChecked(),
            "pad_zero": self.pad_zero.isChecked() if limit_size else False,
            "write_to_file": self.write_to_file.isChecked(),
        }

    def _build_detail_text(self):
        """Build the right-side summary panel."""
        lines = [
            "模式: 字符串按数据字节写入，不走汇编器",
            "编码: %s" % (self.encoding.currentText() or "utf-8"),
            "目标: %s" % (self.start_edit.text().strip() or "(empty)"),
            "范围限制: %s"
            % (
                "%d bytes%s"
                % (
                    self.max_size.value(),
                    "，不足补 00" if self.pad_zero.isChecked() and self.limit_to_range.isChecked() else "",
                )
                if self.limit_to_range.isChecked()
                else "不限制，按字符串实际长度写入"
            ),
            "终止符: %s" % ("追加 \\0" if self.null_terminate.isChecked() else "不追加"),
            "IDA 类型: %s" % ("应用后定义为 C 字符串" if self.define_string.isChecked() else "仅写入数据字节"),
            "",
            "提示:",
            "- 例如输入 ni hao 会写入 6E 69 20 68 61 6F 00",
            "- 修改 data/xref 字符串请用本窗口；修改指令请继续用“修改汇编”",
        ]

        if self.preview_plan is None:
            lines.extend(["", "预览结果:", "- 当前尚未生成字符串预览"])
            return "\n".join(lines)

        plan = self.preview_plan
        lines.extend(
            [
                "",
                "预览结果:",
                "- 起始地址: 0x%X" % plan["start_ea"],
                "- 文本字符数: %d" % len(plan["text"]),
                "- 文本编码长度: %d bytes" % len(plan["raw_text"]),
                "- 总写入长度: %d bytes" % len(plan["patch_bytes"]),
                "- 原字节: %s" % _format_bytes_preview(plan["old_bytes"]),
                "- 新字节: %s" % _format_bytes_preview(plan["patch_bytes"]),
            ]
        )
        return "\n".join(lines)

    def _refresh_detail(self):
        """Refresh the summary panel."""
        self.detail.setPlainText(self._build_detail_text())

    def _preview_string(self):
        """Preview the current string patch request."""
        try:
            debug_log(
                "string_dialog.preview.start",
                trace_id=self.trace_id,
                start_text=self.start_edit.text(),
                encoding=self.encoding.currentText(),
                limit_to_range=self.limit_to_range.isChecked(),
            )
            self.preview_plan = self._compute_plan()
            self.status.setText(
                "预览成功: 将写入 %d bytes 到 0x%X"
                % (len(self.preview_plan["patch_bytes"]), self.preview_plan["start_ea"])
            )
            debug_log(
                "string_dialog.preview.success",
                trace_id=self.trace_id,
                start_ea="0x%X" % self.preview_plan["start_ea"],
                patch_size=len(self.preview_plan["patch_bytes"]),
                encoding=self.preview_plan["encoding"],
            )
        except Exception as exc:
            self.preview_plan = None
            self.status.setText("预览失败: %s" % exc)
            debug_log_exception(
                "string_dialog.preview.failure",
                exc,
                trace_id=self.trace_id,
                start_text=self.start_edit.text(),
                encoding=self.encoding.currentText(),
            )
        self._refresh_detail()

    def _apply_string(self):
        """Apply the current string patch request."""
        transaction = None
        applied_count = 0
        try:
            plan = self._compute_plan()
            debug_log(
                "string_dialog.apply.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % plan["start_ea"],
                patch_size=len(plan["patch_bytes"]),
                encoding=plan["encoding"],
                write_to_file=plan["write_to_file"],
            )
            transaction = begin_patch_transaction(
                "string",
                "修改字符串",
                plan["start_ea"],
                trace_id=self.trace_id,
                meta={
                    "encoding": plan["encoding"],
                    "text_len": len(plan["raw_text"]),
                    "patch_size": len(plan["patch_bytes"]),
                    "null_terminate": plan["null_terminate"],
                    "define_string": plan["define_string"],
                    "write_to_file": plan["write_to_file"],
                },
            )
            record_transaction_operation(
                transaction,
                plan["start_ea"],
                plan["patch_bytes"],
                write_to_file=plan["write_to_file"],
                note="string_patch",
                patch_mode="data",
            )
            file_path = apply_data_patch(
                plan["start_ea"],
                plan["patch_bytes"],
                write_to_file=plan["write_to_file"],
                define_string=plan["define_string"],
                string_len=len(plan["raw_text"]),
                null_terminate=plan["null_terminate"],
            )
            applied_count = 1
            commit_patch_transaction(transaction)
            self.preview_plan = plan
            if plan["write_to_file"]:
                ida_kernwin.msg(
                    "[%s] 已写入字符串 %d bytes 到 0x%X，并同步到输入文件: %s。\n"
                    % (PLUGIN_NAME, len(plan["patch_bytes"]), plan["start_ea"], file_path)
                )
            else:
                ida_kernwin.msg(
                    "[%s] 已写入字符串 %d bytes 到 0x%X。\n"
                    % (PLUGIN_NAME, len(plan["patch_bytes"]), plan["start_ea"])
                )
            debug_log(
                "string_dialog.apply.success",
                trace_id=self.trace_id,
                start_ea="0x%X" % plan["start_ea"],
                patch_size=len(plan["patch_bytes"]),
                write_to_file=plan["write_to_file"],
                file_path=file_path,
            )
            self.dialog.accept()
        except Exception as exc:
            try:
                rollback_partial_transaction(transaction, applied_count)
            except Exception as rollback_exc:
                debug_log_exception(
                    "string_dialog.partial_rollback.failure",
                    rollback_exc,
                    trace_id=self.trace_id,
                )
            self.status.setText("应用失败: %s" % exc)
            debug_log_exception(
                "string_dialog.apply.failure",
                exc,
                trace_id=self.trace_id,
                start_text=self.start_edit.text(),
                encoding=self.encoding.currentText(),
            )
            ida_kernwin.warning("修改字符串失败:\n%s" % exc)
            self._refresh_detail()

    def _toggle_detail_panel(self):
        """Show or hide the right-side detail panel."""
        visible = self.detail.isVisible()
        self.detail.setVisible(not visible)
        self.toggle_detail_btn.setText("显示提示" if visible else "隐藏提示")

    def exec(self):
        """Show the string patch dialog modelessly."""
        return show_modeless_dialog(self)
