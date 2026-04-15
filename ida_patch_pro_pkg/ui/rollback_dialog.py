"""Rollback history dialog."""

import time

import ida_kernwin

from ..constants import PLUGIN_NAME
from ..patching.history_store import (
    clear_patch_history,
    delete_patch_history_entry,
    delete_patch_history_entries,
    load_patch_history,
)
from ..patching.rollback import (
    describe_history_entry,
    entry_can_rollback,
    entry_runtime_status,
    entry_runtime_status_text,
    history_target_ea,
    rollback_transaction,
)
from ..patching.transactions import history_entry_matches_ea
from ..ida_adapter import rebase_history_ea, transaction_imagebase
from .common import load_qt, show_modeless_dialog


class RollbackHistoryDialog:
    """List recorded patch transactions and let the user rollback any selected one."""

    def __init__(self, ctx):
        """Build the rollback history list dialog."""
        _QtCore, QtGui, QtWidgets = load_qt()
        self._QtCore = _QtCore
        self._QtGui = QtGui
        self._QtWidgets = QtWidgets
        self.ctx = ctx
        self.current_ea = history_target_ea(ctx)
        self._rows = []

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("补丁回撤列表")
        self.dialog.resize(1080, 540)

        root = QtWidgets.QVBoxLayout(self.dialog)

        note = QtWidgets.QLabel(
            "这里会列出插件记录过的补丁事务。你可以手动选择要回撤的那一次。"
            " 如果多次修改同一地址，回撤旧事务会直接恢复当时的旧字节，可能覆盖后来的补丁。",
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        current = QtWidgets.QLabel("当前定位地址: 0x%X" % self.current_ea, self.dialog)
        root.addWidget(current)

        body = QtWidgets.QHBoxLayout()

        self.table = QtWidgets.QTableWidget(self.dialog)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["", "状态", "类型", "目标", "代码洞", "写回文件", "时间"])
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._refresh_details)
        self.table.cellDoubleClicked.connect(lambda *_args: self._rollback_selected())
        body.addWidget(self.table, 3)

        self.detail = QtWidgets.QPlainTextEdit(self.dialog)
        self.detail.setReadOnly(True)
        self.detail.setFont(QtGui.QFont("Consolas"))
        body.addWidget(self.detail, 2)

        root.addLayout(body)

        toolbar = QtWidgets.QHBoxLayout()
        self.status = QtWidgets.QLabel("", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.refresh_btn = QtWidgets.QPushButton("刷新列表", self.dialog)
        self.refresh_btn.clicked.connect(self._reload_entries)
        toolbar.addWidget(self.refresh_btn)

        self.rollback_btn = QtWidgets.QPushButton("回撤所选", self.dialog)
        self.rollback_btn.clicked.connect(self._rollback_selected)
        toolbar.addWidget(self.rollback_btn)

        self.delete_btn = QtWidgets.QPushButton("删除记录", self.dialog)
        self.delete_btn.clicked.connect(self._delete_selected_entry)
        toolbar.addWidget(self.delete_btn)

        self.delete_checked_btn = QtWidgets.QPushButton("删除勾选", self.dialog)
        self.delete_checked_btn.clicked.connect(self._delete_checked_entries)
        toolbar.addWidget(self.delete_checked_btn)

        self.clear_btn = QtWidgets.QPushButton("清空列表", self.dialog)
        self.clear_btn.clicked.connect(self._clear_history_entries)
        toolbar.addWidget(self.clear_btn)

        self.close_btn = QtWidgets.QPushButton("关闭", self.dialog)
        self.close_btn.clicked.connect(self.dialog.close)
        toolbar.addWidget(self.close_btn)
        root.addLayout(toolbar)

        self._reload_entries()

    def _build_rows(self):
        """Collect display rows from persisted history."""
        rows = []
        for entry in reversed(load_patch_history()):
            meta = entry.get("meta") or {}
            stored_imagebase = transaction_imagebase(meta)
            target_ea = rebase_history_ea(entry.get("target_ea", 0), stored_imagebase)
            cave_start = rebase_history_ea(meta.get("cave_start"), stored_imagebase)
            runtime_status = entry_runtime_status(entry)
            rows.append(
                {
                    "entry": entry,
                    "runtime_status": runtime_status,
                    "can_rollback": entry_can_rollback(entry),
                    "target_ea": target_ea,
                    "cave_start": cave_start,
                    "write_to_file": bool(meta.get("write_to_file")),
                    "hits_current_ea": history_entry_matches_ea(entry, self.current_ea),
                }
            )
        return rows

    def _selected_row(self):
        """Return the currently selected history row, or None."""
        row = self.table.currentRow()
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]

    def _checked_rows(self):
        """Return all checked history rows."""
        checked = []
        for index in range(len(self._rows)):
            item = self.table.item(index, 0)
            if item is not None and item.checkState() == self._QtCore.Qt.Checked:
                checked.append(self._rows[index])
        return checked

    def _select_preferred_row(self):
        """Pick a sensible default selection after reloading the list."""
        if not self._rows:
            return
        for index, row in enumerate(self._rows):
            if row["hits_current_ea"] and row["can_rollback"]:
                self.table.selectRow(index)
                return
        for index, row in enumerate(self._rows):
            if row["can_rollback"]:
                self.table.selectRow(index)
                return
        self.table.selectRow(0)

    def _reload_entries(self):
        """Reload history from disk and refresh the table/detail panel."""
        QtGui = self._QtGui
        QtWidgets = self._QtWidgets
        self._rows = self._build_rows()
        self.table.setRowCount(len(self._rows))

        font = QtGui.QFont("Consolas")
        for row_index, row in enumerate(self._rows):
            entry = row["entry"]
            created_at = entry.get("created_at")
            checked_item = QtWidgets.QTableWidgetItem("")
            checked_item.setFlags(
                QtWidgets.QTableWidgetItem().flags()
                | self._QtCore.Qt.ItemIsUserCheckable
            )
            checked_item.setCheckState(self._QtCore.Qt.Unchecked)
            self.table.setItem(row_index, 0, checked_item)
            values = [
                entry_runtime_status_text(row["runtime_status"]),
                entry.get("label") or entry.get("kind") or "",
                "0x%X" % (row["target_ea"] or 0),
                ("0x%X" % row["cave_start"]) if row["cave_start"] is not None else "",
                "是" if row["write_to_file"] else "否",
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_at)) if created_at else "",
            ]
            for value_index, value in enumerate(values, start=1):
                item = QtWidgets.QTableWidgetItem(value)
                if value_index in (3, 4):
                    item.setFont(font)
                self.table.setItem(row_index, value_index, item)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        for col_index in range(1, 6):
            header.setSectionResizeMode(col_index, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QtWidgets.QHeaderView.Stretch)

        if self._rows:
            self.status.setText("共 %d 条补丁事务记录。" % len(self._rows))
            self.clear_btn.setEnabled(True)
            self._select_preferred_row()
        else:
            self.status.setText("当前还没有插件补丁记录。")
            self.detail.setPlainText("")
            self.rollback_btn.setEnabled(False)
            self.delete_btn.setEnabled(False)
            self.delete_checked_btn.setEnabled(False)
            self.clear_btn.setEnabled(False)

        self._refresh_details()

    def _refresh_details(self):
        """Refresh the right-side detail panel for the selected row."""
        row = self._selected_row()
        if row is None:
            self.detail.setPlainText("")
            self.rollback_btn.setEnabled(False)
            self.delete_btn.setEnabled(False)
            return

        lines = [
            "状态: %s" % entry_runtime_status_text(row["runtime_status"]),
            describe_history_entry(row["entry"]),
        ]
        if row["hits_current_ea"]:
            lines.append("命中当前地址: 是")
        else:
            lines.append("命中当前地址: 否")
        if row["runtime_status"] == "stale":
            lines.append("说明: 历史记录已标成回撤，但当前 IDB 里仍有残留补丁字节。")
        elif not row["can_rollback"]:
            lines.append("说明: 这条记录已经回撤完成，目前仅供查看。")
        lines.append("管理: 删除记录只会从列表里移除，不会自动改动当前 IDB 或输入文件。")

        self.detail.setPlainText("\n\n".join(lines))
        self.rollback_btn.setEnabled(row["can_rollback"])
        self.delete_btn.setEnabled(True)
        self.delete_checked_btn.setEnabled(bool(self._rows))
        self.clear_btn.setEnabled(bool(self._rows))

    def _rollback_selected(self):
        """Rollback the currently selected history transaction."""
        row = self._selected_row()
        if row is None:
            return
        if not row["can_rollback"]:
            ida_kernwin.warning("当前所选事务已经回撤完成，不能再次回撤。")
            return

        prompt = "即将回撤所选补丁事务："
        if row["runtime_status"] == "stale":
            prompt = "检测到这条事务存在 IDB 残留，将执行一次修复性回撤："
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "%s\n\n%s\n\n是否继续？" % (prompt, describe_history_entry(row["entry"])),
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return

        rollback_transaction(row["entry"])
        ida_kernwin.msg(
            "[%s] 已回撤补丁事务: %s @ 0x%X。\n"
            % (
                PLUGIN_NAME,
                row["entry"].get("label") or row["entry"].get("kind"),
                row["target_ea"] or 0,
            )
        )
        self._reload_entries()

    def _delete_selected_entry(self):
        """Delete the selected history record without touching patch bytes."""
        row = self._selected_row()
        if row is None:
            return
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "即将删除这条补丁历史记录。\n\n%s\n\n"
            "注意：这不会自动回撤当前 IDB 或输入文件里的补丁，只是把它从列表中移除。\n\n是否继续？"
            % describe_history_entry(row["entry"]),
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return
        if delete_patch_history_entry(row["entry"].get("tx_id")):
            self.status.setText("已删除所选补丁历史记录。")
            self._reload_entries()

    def _delete_checked_entries(self):
        """Delete all checked history records without touching patch bytes."""
        rows = self._checked_rows()
        if not rows:
            self.status.setText("当前没有勾选任何补丁历史记录。")
            return
        preview = "\n".join("- %s" % describe_history_entry(row["entry"]) for row in rows[:4])
        if len(rows) > 4:
            preview += "\n- ..."
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "即将删除勾选的 %d 条补丁历史记录。\n\n%s\n\n"
            "注意：这不会自动回撤当前 IDB 或输入文件里的补丁，只是把这些记录从列表中移除。\n\n是否继续？"
            % (len(rows), preview),
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return
        deleted_count = delete_patch_history_entries([row["entry"].get("tx_id") for row in rows])
        if deleted_count > 0:
            self.status.setText("已删除勾选补丁历史记录 %d 条。" % deleted_count)
            self._reload_entries()

    def _clear_history_entries(self):
        """Delete all history records without touching current patch bytes."""
        if not self._rows:
            return
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "即将清空补丁回撤列表中的全部历史记录。\n\n"
            "注意：这不会自动回撤当前 IDB 或输入文件里的补丁，只是删除列表记录。\n\n是否继续？",
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return
        clear_patch_history()
        self.status.setText("已清空全部补丁历史记录。")
        self._reload_entries()

    def exec(self):
        """Show the rollback dialog modelessly so IDA stays interactive."""
        return show_modeless_dialog(self)
