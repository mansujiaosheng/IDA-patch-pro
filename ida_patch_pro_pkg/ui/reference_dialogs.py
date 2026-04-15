"""Reference dialogs for syntax and registers."""

from ..data import ARCH_REGISTER_HELP, ARCH_SYNTAX_HELP
from .common import load_qt


class ReferenceTableDialog:
    """Shared searchable table dialog used by syntax and register references."""

    def __init__(self, title, note_text, headers, rows, monospace_columns=None, parent=None):
        """Build a generic filterable reference table."""
        _QtCore, QtGui, QtWidgets = load_qt()
        monospace_columns = set(monospace_columns or [])

        self.dialog = QtWidgets.QDialog(parent)
        self.dialog.setWindowTitle(title)
        self.dialog.resize(1080, 520)
        self._rows = list(rows)
        self._QtWidgets = QtWidgets

        layout = QtWidgets.QVBoxLayout(self.dialog)

        note = QtWidgets.QLabel(note_text, self.dialog)
        note.setWordWrap(True)
        layout.addWidget(note)

        self.search_edit = QtWidgets.QLineEdit(self.dialog)
        self.search_edit.setPlaceholderText("输入关键字过滤，例如 mov / rsp / xmm0 / return / 参数")
        self.search_edit.textChanged.connect(self._apply_filter)
        layout.addWidget(self.search_edit)

        self.table = QtWidgets.QTableWidget(self.dialog)
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setRowCount(len(self._rows))
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)

        monospace_font = QtGui.QFont("Consolas")
        for row_index, row in enumerate(self._rows):
            for col_index, value in enumerate(row):
                item = QtWidgets.QTableWidgetItem(value)
                if col_index in monospace_columns:
                    item.setFont(monospace_font)
                self.table.setItem(row_index, col_index, item)

        header = self.table.horizontalHeader()
        for col_index in range(max(0, len(headers) - 1)):
            header.setSectionResizeMode(col_index, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(len(headers) - 1, QtWidgets.QHeaderView.Stretch)
        layout.addWidget(self.table)

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close, parent=self.dialog)
        buttons.rejected.connect(self.dialog.reject)
        buttons.accepted.connect(self.dialog.accept)
        layout.addWidget(buttons)

    def _apply_filter(self, text):
        """Hide rows that do not match the current search keyword."""
        needle = (text or "").strip().lower()
        for row_index, row in enumerate(self._rows):
            haystack = " ".join(row).lower()
            self.table.setRowHidden(row_index, bool(needle) and needle not in haystack)

    def exec(self):
        """Show the reference dialog modally."""
        return self.dialog.exec()


class SyntaxHelpDialog:
    """Architecture-specific syntax quick reference dialog."""

    def __init__(self, category, parent=None):
        """Build the quick reference table for the selected architecture."""
        info = ARCH_SYNTAX_HELP[category]
        self.reference = ReferenceTableDialog(
            "汇编语法帮助 - %s" % category,
            info["note"],
            ["示例", "语法", "典型十六进制", "典型字节长度", "含义"],
            info["rows"],
            monospace_columns=(0, 1, 2),
            parent=parent,
        )

    def exec(self):
        """Show the syntax help dialog modally."""
        return self.reference.exec()


class RegisterHelpDialog:
    """Architecture-specific register quick reference dialog."""

    def __init__(self, category, parent=None):
        """Build the register reference table for the selected architecture."""
        info = ARCH_REGISTER_HELP[category]
        self.reference = ReferenceTableDialog(
            "寄存器速查表 - %s" % category,
            info["note"],
            ["寄存器", "类别", "常见用途", "补充说明"],
            info["rows"],
            monospace_columns=(0,),
            parent=parent,
        )

    def exec(self):
        """Show the register help dialog modally."""
        return self.reference.exec()
