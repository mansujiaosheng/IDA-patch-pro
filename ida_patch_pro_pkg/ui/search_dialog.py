"""Assembly search dialog."""

import time

import ida_idaapi
import ida_kernwin

from ..asm.operands import processor_key
from ..asm.search_help import build_search_usage_text
from ..asm.search import SEARCH_MODE_EXACT, SEARCH_MODE_TEXT, search_assembly
from ..ida_adapter import (
    current_database_identity,
    current_database_label,
    database_max_ea,
    database_min_ea,
    function_range_for_ea,
    resolve_ea_text,
    segment_range_for_ea,
)
from ..logging_utils import debug_log, debug_log_exception, format_bytes_hex, make_trace_id
from ..patching.search_history import (
    clear_search_history,
    load_search_history,
    remember_search_history,
    save_search_history,
)
from ..patching.selection import current_ea, get_original_entries, join_entry_asm_lines
from .reference_dialogs import RegisterHelpDialog, SyntaxHelpDialog
from .common import load_qt, show_modeless_dialog


class AssemblySearchDialog:
    """Search the current database for an assembly pattern."""

    def __init__(self, ctx):
        """Build the search dialog from the current disassembly context."""
        _QtCore, QtGui, QtWidgets = load_qt()
        self._QtCore = _QtCore
        self.ctx = ctx
        self.arch_key = processor_key()
        self.current_ea = current_ea(ctx)
        self.project_key = current_database_identity()
        self.project_label = current_database_label()
        self.trace_id = make_trace_id("search", self.current_ea)
        self._QtGui = QtGui
        self._QtWidgets = QtWidgets
        self.search_result = None
        self._rows = []
        self._history_entries = []
        self.validation_entries = get_original_entries(ctx, log_events=True)

        default_start, default_end, default_desc = self._default_range()
        default_query = join_entry_asm_lines(self.validation_entries)

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("汇编搜索")
        self.dialog.resize(1180, 560)

        root = QtWidgets.QVBoxLayout(self.dialog)
        note = QtWidgets.QLabel(
            "说明: 搜索会从每个候选指令头重新汇编你的查询文本，再与当前位置实际字节比较。"
            " 大多数情况下请填写完整指令，例如 `cmp eax, ebx`；`nop` 这类零操作数指令可直接只写一个单词。"
            " 相对跳转、符号目标和地址相关编码会按候选地址重新计算。",
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        current = QtWidgets.QLabel(
            "默认范围: %s | 当前地址: 0x%X | 当前数据库: %s"
            % (default_desc, self.current_ea, self.project_label),
            self.dialog,
        )
        current.setWordWrap(True)
        root.addWidget(current)

        range_row = QtWidgets.QHBoxLayout()
        range_row.addWidget(QtWidgets.QLabel("起始地址", self.dialog))
        self.start_edit = QtWidgets.QLineEdit("0x%X" % default_start, self.dialog)
        range_row.addWidget(self.start_edit, 1)
        range_row.addWidget(QtWidgets.QLabel("结束地址(不含)", self.dialog))
        self.end_edit = QtWidgets.QLineEdit("0x%X" % default_end, self.dialog)
        range_row.addWidget(self.end_edit, 1)
        range_row.addWidget(QtWidgets.QLabel("结果上限", self.dialog))
        self.max_results = QtWidgets.QSpinBox(self.dialog)
        self.max_results.setRange(1, 5000)
        self.max_results.setValue(200)
        range_row.addWidget(self.max_results)
        range_row.addWidget(QtWidgets.QLabel("搜索方式", self.dialog))
        self.mode_combo = QtWidgets.QComboBox(self.dialog)
        self.mode_combo.addItem("精确汇编", SEARCH_MODE_EXACT)
        self.mode_combo.addItem("助记符/寄存器/文本", SEARCH_MODE_TEXT)
        self.mode_combo.currentIndexChanged.connect(self._on_search_mode_changed)
        range_row.addWidget(self.mode_combo)
        root.addLayout(range_row)

        body = QtWidgets.QHBoxLayout()
        history_col = QtWidgets.QVBoxLayout()
        history_col.addWidget(QtWidgets.QLabel("搜索历史", self.dialog))
        self.history_list = QtWidgets.QListWidget(self.dialog)
        self.history_list.itemDoubleClicked.connect(lambda *_args: self._apply_selected_history())
        history_col.addWidget(self.history_list, 1)
        history_toolbar = QtWidgets.QHBoxLayout()
        self.history_apply_btn = QtWidgets.QPushButton("载入", self.dialog)
        self.history_apply_btn.clicked.connect(self._apply_selected_history)
        history_toolbar.addWidget(self.history_apply_btn)
        self.history_delete_btn = QtWidgets.QPushButton("删除", self.dialog)
        self.history_delete_btn.clicked.connect(self._delete_selected_history)
        history_toolbar.addWidget(self.history_delete_btn)
        self.history_delete_checked_btn = QtWidgets.QPushButton("删勾选", self.dialog)
        self.history_delete_checked_btn.clicked.connect(self._delete_checked_history)
        history_toolbar.addWidget(self.history_delete_checked_btn)
        self.history_clear_btn = QtWidgets.QPushButton("清空", self.dialog)
        self.history_clear_btn.clicked.connect(self._clear_history)
        history_toolbar.addWidget(self.history_clear_btn)
        history_col.addLayout(history_toolbar)
        body.addLayout(history_col, 1)

        center = QtWidgets.QVBoxLayout()
        self.editor = QtWidgets.QPlainTextEdit(self.dialog)
        font = QtGui.QFont("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)
        self.editor.setFont(font)
        self.editor.setPlainText(default_query)
        self.editor.textChanged.connect(self._refresh_detail)
        center.addWidget(self.editor, 2)

        self.table = QtWidgets.QTableWidget(self.dialog)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["地址", "大小", "机器码", "反汇编"])
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._refresh_detail)
        self.table.cellDoubleClicked.connect(lambda *_args: self._goto_selected())
        center.addWidget(self.table, 3)
        body.addLayout(center, 3)

        self.detail = QtWidgets.QPlainTextEdit(self.dialog)
        self.detail.setReadOnly(True)
        self.detail.setFont(font)
        body.addWidget(self.detail, 2)
        root.addLayout(body)

        toolbar = QtWidgets.QHBoxLayout()
        self.status = QtWidgets.QLabel("当前尚未开始搜索。", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.search_btn = QtWidgets.QPushButton("开始搜索", self.dialog)
        self.search_btn.clicked.connect(self._run_search)
        toolbar.addWidget(self.search_btn)

        self.goto_btn = QtWidgets.QPushButton("跳转所选", self.dialog)
        self.goto_btn.clicked.connect(self._goto_selected)
        toolbar.addWidget(self.goto_btn)

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

        self.close_btn = QtWidgets.QPushButton("关闭", self.dialog)
        self.close_btn.clicked.connect(self.dialog.close)
        toolbar.addWidget(self.close_btn)
        root.addLayout(toolbar)

        self._reload_history()
        self._update_editor_placeholder()
        self._refresh_detail()
        debug_log(
            "assembly_search_dialog.open",
            trace_id=self.trace_id,
            current_ea="0x%X" % self.current_ea,
            start_ea="0x%X" % default_start,
            end_ea="0x%X" % default_end,
            query_text=default_query,
        )

    def _current_search_mode(self):
        """Return the currently selected search mode."""
        return self.mode_combo.currentData() or SEARCH_MODE_EXACT

    def _search_mode_label(self, mode):
        """Return one short user-facing label for the given search mode."""
        return "精确汇编" if mode == SEARCH_MODE_EXACT else "文本"

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

    def _update_editor_placeholder(self):
        """Refresh editor placeholder text according to current search mode."""
        if self._current_search_mode() == SEARCH_MODE_TEXT:
            self.editor.setPlaceholderText("例如:\ncmp\neax\nprintf")
        else:
            self.editor.setPlaceholderText("例如:\ncmp eax, ebx\njz loc_140001234")

    def _on_search_mode_changed(self):
        """Refresh usage text when the search mode changes."""
        self._update_editor_placeholder()
        self._refresh_detail()

    def _history_item_label(self, entry):
        """Build a compact label for one history item."""
        query_text = entry.get("query_text") or ""
        first_line = query_text.splitlines()[0].strip() if query_text else ""
        if len(first_line) > 28:
            first_line = first_line[:27] + "..."
        suffix = ""
        line_count = len([line for line in query_text.splitlines() if line.strip()])
        if line_count > 1:
            suffix = " (+%d)" % (line_count - 1)
        result = entry.get("search_result") or {}
        result_count = int(result.get("result_count", 0) or 0)
        return "[%s][%d] %s%s" % (
            self._search_mode_label(entry.get("mode")),
            result_count,
            first_line or "(empty)",
            suffix,
        )

    def _reload_history(self):
        """Reload the persisted search history list."""
        self._history_entries = load_search_history(project_key=self.project_key)
        self.history_list.clear()
        for entry in self._history_entries:
            item = self._QtWidgets.QListWidgetItem(self._history_item_label(entry))
            item.setFlags(item.flags() | self._QtCore.Qt.ItemIsUserCheckable)
            item.setCheckState(self._QtCore.Qt.Unchecked)
            result = entry.get("search_result") or {}
            item.setToolTip(
                "%s | 命中 %d | %s\n\n%s"
                % (
                    self._search_mode_label(entry.get("mode")),
                    int(result.get("result_count", 0) or 0),
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.get("created_at") or 0)),
                    entry.get("query_text") or "",
                )
            )
            self.history_list.addItem(item)
        has_history = bool(self._history_entries)
        self.history_apply_btn.setEnabled(has_history)
        self.history_delete_btn.setEnabled(has_history)
        self.history_delete_checked_btn.setEnabled(has_history)
        self.history_clear_btn.setEnabled(has_history)

    def _checked_history_indexes(self):
        """Return all checked history item indexes."""
        indexes = []
        for index in range(self.history_list.count()):
            item = self.history_list.item(index)
            if item is not None and item.checkState() == self._QtCore.Qt.Checked:
                indexes.append(index)
        return indexes

    def _selected_history_index(self):
        """Return the current history-list index, or None."""
        row = self.history_list.currentRow()
        if row < 0 or row >= len(self._history_entries):
            return None
        return row

    def _apply_selected_history(self):
        """Load the selected history entry back into the search form."""
        index = self._selected_history_index()
        if index is None:
            return
        entry = self._history_entries[index]
        for combo_index in range(self.mode_combo.count()):
            if self.mode_combo.itemData(combo_index) == entry.get("mode"):
                self.mode_combo.setCurrentIndex(combo_index)
                break
        self.editor.setPlainText(entry.get("query_text") or "")
        result = entry.get("search_result")
        if result:
            self.start_edit.setText("0x%X" % int(result.get("start_ea", 0) or 0))
            self.end_edit.setText("0x%X" % int(result.get("end_ea", 0) or 0))
            self.max_results.setValue(max(1, int(result.get("max_results", 1) or 1)))
            self.search_result = result
            self._reload_results()
            self.status.setText("已恢复历史搜索结果快照；如需最新结果可再次搜索。")
        else:
            self.search_result = None
            self._rows = []
            self.table.setRowCount(0)
            self._refresh_detail()
            self.status.setText("已载入搜索历史，可直接再次搜索。")

    def _delete_selected_history(self):
        """Delete the selected persisted search-history entry."""
        index = self._selected_history_index()
        if index is None:
            return
        self._delete_history_indexes([index], label="所选")

    def _delete_checked_history(self):
        """Delete all checked persisted search-history entries."""
        indexes = self._checked_history_indexes()
        if not indexes:
            self.status.setText("当前没有勾选任何搜索历史。")
            return
        self._delete_history_indexes(indexes, label="勾选")

    def _delete_history_indexes(self, indexes, label):
        """Delete the specified history indexes after confirmation."""
        entries = list(self._history_entries)
        targets = [entries[index] for index in sorted(set(indexes)) if 0 <= index < len(entries)]
        if not targets:
            return
        preview = "\n".join(
            "- [%s] %s"
            % (self._search_mode_label(entry.get("mode")), (entry.get("query_text") or "").splitlines()[0].strip())
            for entry in targets[:6]
        )
        if len(targets) > 6:
            preview += "\n- ..."
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "即将删除%s %d 条搜索历史：\n\n%s\n\n是否继续？"
            % (label, len(targets), preview),
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return
        kept = [entry for idx, entry in enumerate(entries) if idx not in set(indexes)]
        save_search_history(kept)
        self._reload_history()
        self.status.setText("已删除%s搜索历史 %d 条。" % (label, len(targets)))

    def _clear_history(self):
        """Delete all persisted search-history entries."""
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "即将清空当前数据库 `%s` 的所有搜索历史记录。\n\n是否继续？" % self.project_label,
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return
        clear_search_history(project_key=self.project_key)
        self._reload_history()
        self.status.setText("已清空搜索历史。")

    def _default_range(self):
        """Choose a default search range from the current selection or segment."""
        widget = getattr(self.ctx, "widget", None)
        has_selection, start_ea, end_ea = ida_kernwin.read_range_selection(widget)
        if has_selection and start_ea != ida_idaapi.BADADDR and end_ea > start_ea:
            return int(start_ea), int(end_ea), "当前选区"

        func = function_range_for_ea(self.current_ea)
        if func is not None:
            return func["start_ea"], func["end_ea"], "当前函数 %s" % (func["name"] or "(unnamed)")

        seg = segment_range_for_ea(self.current_ea)
        if seg is not None:
            return seg["start_ea"], seg["end_ea"], "当前段 %s" % (seg["name"] or "(unnamed)")
        return database_min_ea(), database_max_ea(), "整个数据库"

    def _parsed_range(self):
        """Parse the current search range fields."""
        start_ea = resolve_ea_text(self.start_edit.text())
        end_ea = resolve_ea_text(self.end_edit.text())
        if start_ea is None or end_ea is None:
            raise RuntimeError("起始/结束地址无法解析，请输入有效地址或符号。")
        if end_ea <= start_ea:
            raise RuntimeError("结束地址必须大于起始地址。")
        return start_ea, end_ea

    def _selected_row(self):
        """Return the currently selected search result row."""
        row = self.table.currentRow()
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]

    def _reload_results(self):
        """Reload the results table from the last completed search."""
        QtGui = self._QtGui
        QtWidgets = self._QtWidgets
        results = (self.search_result or {}).get("results") or []
        self._rows = list(results)
        self.table.setRowCount(len(self._rows))

        mono = QtGui.QFont("Consolas")
        for row_index, row in enumerate(self._rows):
            values = [
                "0x%X" % row["ea"],
                str(row["size"]),
                format_bytes_hex(row["bytes"]),
                row.get("disasm_text") or "",
            ]
            for col_index, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                if col_index in (0, 2):
                    item.setFont(mono)
                self.table.setItem(row_index, col_index, item)

        header = self.table.horizontalHeader()
        for col_index in range(3):
            header.setSectionResizeMode(col_index, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)
        if self._rows:
            self.table.selectRow(0)
        self._refresh_detail()

    def _detail_text(self):
        """Build the right-side details for the selected row or current search state."""
        lines = ["架构: %s" % self.arch_key, "搜索方式: %s" % self._search_mode_label(self._current_search_mode())]
        try:
            start_ea, end_ea = self._parsed_range()
            lines.append("范围: 0x%X - 0x%X" % (start_ea, end_ea))
        except Exception as exc:
            lines.append("范围: %s" % exc)

        row = self._selected_row()
        if row is None:
            if self.search_result is not None:
                lines.extend(
                    [
                        "搜索统计:",
                        "- 扫描候选头: %d" % self.search_result.get("scanned_count", 0),
                        "- 命中数量: %d" % self.search_result.get("result_count", 0),
                    ]
                )
            else:
                lines.extend(["", "搜索统计:", "- 当前尚未开始搜索"])
            lines.extend(["", build_search_usage_text(self.editor.toPlainText(), self._current_search_mode())])
            return "\n".join(lines)

        lines.extend(
            [
                "",
                "所选结果:",
                "- 地址: 0x%X" % row["ea"],
                "- 大小: %d bytes" % row["size"],
                "- 机器码: %s" % format_bytes_hex(row["bytes"]),
                "- 反汇编: %s" % (row.get("disasm_text") or "(none)"),
            ]
        )
        if row.get("notes"):
            lines.append("")
            lines.append("兼容说明:")
            for note in row["notes"]:
                lines.append("- %s" % note)
        lines.extend(["", build_search_usage_text(self.editor.toPlainText(), self._current_search_mode())])
        return "\n".join(lines)

    def _refresh_detail(self):
        """Refresh the right-side detail panel."""
        self.detail.setPlainText(self._detail_text())
        self.goto_btn.setEnabled(self._selected_row() is not None)

    def _run_search(self):
        """Execute the current assembly search request."""
        wait_box_visible = False

        def progress(info):
            nonlocal wait_box_visible
            message = (
                "正在执行汇编搜索...\n"
                "范围: 0x%X - 0x%X\n"
                "当前: 0x%X\n"
                "已扫描: %d\n"
                "已命中: %d\n"
                "按 Esc 取消"
            ) % (
                info["start_ea"],
                info["end_ea"],
                info["current_ea"],
                info["scanned_count"],
                info["result_count"],
            )
            if wait_box_visible:
                ida_kernwin.replace_wait_box(message)
            else:
                ida_kernwin.show_wait_box(message)
                wait_box_visible = True
            return not ida_kernwin.user_cancelled()

        try:
            start_ea, end_ea = self._parsed_range()
            query_text = self.editor.toPlainText().strip()
            self.search_btn.setEnabled(False)
            self.goto_btn.setEnabled(False)
            self.status.setText("正在搜索，请稍候...")
            debug_log(
                "assembly_search_dialog.run.start",
                trace_id=self.trace_id,
                start_ea="0x%X" % start_ea,
                end_ea="0x%X" % end_ea,
                query_text=query_text,
                max_results=self.max_results.value(),
            )
            self.search_result = search_assembly(
                query_text,
                start_ea,
                end_ea,
                arch_key=self.arch_key,
                max_results=self.max_results.value(),
                validation_entries=self.validation_entries,
                validation_ea=self.current_ea,
                progress=progress,
                mode=self._current_search_mode(),
            )
            self._history_entries = remember_search_history(
                query_text,
                self._current_search_mode(),
                search_result=self.search_result,
            )
            self._reload_history()
            self.status.setText(
                "搜索完成: 扫描 %d 个候选头，命中 %d 条。"
                % (
                    self.search_result["scanned_count"],
                    self.search_result["result_count"],
                )
            )
            self._reload_results()
            debug_log(
                "assembly_search_dialog.run.success",
                trace_id=self.trace_id,
                scanned_count=self.search_result["scanned_count"],
                result_count=self.search_result["result_count"],
            )
        except Exception as exc:
            self.search_result = None
            self._rows = []
            self.table.setRowCount(0)
            cancelled = str(exc) == "搜索已取消。"
            self.status.setText(("搜索已取消。" if cancelled else "搜索失败: %s" % exc))
            self._refresh_detail()
            debug_log_exception(
                "assembly_search_dialog.run.failure",
                exc,
                trace_id=self.trace_id,
                query_text=self.editor.toPlainText().strip(),
            )
            if not cancelled:
                ida_kernwin.warning("汇编搜索失败:\n%s" % exc)
        finally:
            if wait_box_visible:
                try:
                    ida_kernwin.hide_wait_box()
                except Exception:
                    pass
            self.search_btn.setEnabled(True)
            self._refresh_detail()

    def _goto_selected(self):
        """Jump to the currently selected search result."""
        row = self._selected_row()
        if row is None:
            return
        ida_kernwin.jumpto(row["ea"])

    def exec(self):
        """Show the search dialog modelessly."""
        return show_modeless_dialog(self)
