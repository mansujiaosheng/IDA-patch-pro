"""Shared IDA-View style patch table widgets."""

from ..logging_utils import debug_log, format_bytes_hex
from .common import load_qt

COL_ADDRESS = 0
COL_BYTES = 1
COL_ASSEMBLY = 2


def _qt_key(QtCore, name):
    try:
        return getattr(QtCore.Qt.Key, name)
    except Exception:
        return getattr(QtCore.Qt, name)


def _qt_event_type(QtCore, name):
    try:
        return getattr(QtCore.QEvent.Type, name)
    except Exception:
        return getattr(QtCore.QEvent, name)


def _enum_value(value):
    try:
        return int(value.value)
    except Exception:
        return int(value)


def _item_flags(QtCore, editable=False):
    """Build table item flags without relying on PyQt5 enum shims."""
    try:
        item_flag = QtCore.Qt.ItemFlag
        flags_value = item_flag.ItemIsEnabled.value | item_flag.ItemIsSelectable.value
        if editable:
            flags_value |= item_flag.ItemIsEditable.value
        return item_flag(flags_value)
    except Exception:
        flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable
        if editable:
            flags |= QtCore.Qt.ItemIsEditable
        return flags


def _edit_triggers(QtWidgets):
    """Build edit-trigger flags without relying on PyQt5 enum shims."""
    try:
        trigger = QtWidgets.QAbstractItemView.EditTrigger
        flags_value = (
            trigger.DoubleClicked.value
            | trigger.EditKeyPressed.value
            | trigger.SelectedClicked.value
        )
        return trigger(flags_value)
    except Exception:
        return (
            QtWidgets.QAbstractItemView.DoubleClicked
            | QtWidgets.QAbstractItemView.EditKeyPressed
            | QtWidgets.QAbstractItemView.SelectedClicked
        )


def create_patch_table(parent, font=None, editable_bytes=True):
    """Create the address/bytes/assembly table used by patch dialogs."""
    _QtCore, _QtGui, QtWidgets = load_qt()
    table = QtWidgets.QTableWidget(parent)
    table._patch_table_editable_bytes = bool(editable_bytes)  # pylint: disable=protected-access
    table.setColumnCount(3)
    table.setHorizontalHeaderLabels(["Address", "Bytes", "Assembly"])
    table.setEditTriggers(_edit_triggers(QtWidgets))
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectItems)
    table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    table.setAlternatingRowColors(False)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    table.horizontalHeader().setSectionResizeMode(COL_ADDRESS, QtWidgets.QHeaderView.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(COL_BYTES, QtWidgets.QHeaderView.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(COL_ASSEMBLY, QtWidgets.QHeaderView.Stretch)
    table.setWordWrap(False)
    table.setShowGrid(False)
    if font is not None:
        table.setFont(font)
    table.setStyleSheet(
        "QTableWidget { color: #0000cc; background: white; }"
        "QTableWidget::item:selected { background: #bfe8c2; color: #0000cc; }"
        "QHeaderView::section { padding: 3px 6px; }"
    )
    return table


class PatchTableKeyFilter:
    """Small QObject-backed key filter for patch tables."""

    def __init__(self, table, on_enter=None, on_delete=None, on_space=None):
        QtCore, _QtGui, QtWidgets = load_qt()
        key_press = _enum_value(_qt_event_type(QtCore, "KeyPress"))
        shortcut_override = _enum_value(_qt_event_type(QtCore, "ShortcutOverride"))
        enter_keys = {_enum_value(_qt_key(QtCore, "Key_Return")), _enum_value(_qt_key(QtCore, "Key_Enter"))}
        delete_key = _enum_value(_qt_key(QtCore, "Key_Delete"))
        insert_keys = {_enum_value(_qt_key(QtCore, "Key_Space")), _enum_value(_qt_key(QtCore, "Key_Insert"))}

        class _Filter(QtCore.QObject):
            def _is_table_object(self, watched):
                current = watched
                while current is not None:
                    if current is table:
                        return True
                    try:
                        current = current.parent()
                    except Exception:
                        return False
                return False

            def _is_table_view_object(self, watched):
                return watched is table or watched is table.viewport()

            def _finish_editor(self, watched):
                if watched is table or watched is table.viewport():
                    return
                try:
                    table.commitData(watched)
                except Exception:
                    pass
                try:
                    hint = QtWidgets.QAbstractItemDelegate.EndEditHint.NoHint
                except Exception:
                    hint = QtWidgets.QAbstractItemDelegate.NoHint
                try:
                    table.closeEditor(watched, hint)
                except Exception:
                    pass

            def eventFilter(self, watched, event):
                event_type = _enum_value(event.type())
                if event_type in (key_press, shortcut_override):
                    in_table = self._is_table_object(watched)
                    in_table_view = self._is_table_view_object(watched)
                    if not in_table:
                        return False
                    key = int(event.key())
                    if key in enter_keys:
                        event.accept()
                        if event_type == shortcut_override:
                            return True
                        if on_enter is not None:
                            self._finish_editor(watched)
                            debug_log("patch_table.key", key="enter")
                            QtCore.QTimer.singleShot(0, on_enter)
                            return True
                    if in_table_view and key == delete_key:
                        event.accept()
                        if event_type == shortcut_override:
                            return True
                        if on_delete is not None:
                            debug_log("patch_table.key", key="delete")
                            QtCore.QTimer.singleShot(0, on_delete)
                            return True
                    if in_table_view and key in insert_keys:
                        event.accept()
                        if event_type == shortcut_override:
                            return True
                        if on_space is not None:
                            debug_log("patch_table.key", key="insert")
                            QtCore.QTimer.singleShot(0, on_space)
                            return True
                return False

        class _Delegate(QtWidgets.QStyledItemDelegate):
            def createEditor(self, parent, option, index):
                editor = super().createEditor(parent, option, index)
                if editor is not None:
                    editor.installEventFilter(self._key_filter)
                return editor

        self.filter = _Filter(table)
        self.delegate = _Delegate(table)
        self.delegate._key_filter = self.filter  # pylint: disable=protected-access
        table.setItemDelegate(self.delegate)
        table.installEventFilter(self.filter)
        table.viewport().installEventFilter(self.filter)
        app = QtWidgets.QApplication.instance()
        if app is not None:
            app.installEventFilter(self.filter)


def install_patch_table_key_filter(table, on_enter=None, on_delete=None, on_space=None):
    """Install Enter/Delete/Space handling using a real QObject event filter."""
    table._patch_table_key_filter = PatchTableKeyFilter(  # pylint: disable=protected-access
        table,
        on_enter=on_enter,
        on_delete=on_delete,
        on_space=on_space,
    )


def set_patch_table_rows(table, rows):
    """Replace table contents from row dictionaries."""
    QtCore, QtGui, QtWidgets = load_qt()
    editable_bytes = bool(getattr(table, "_patch_table_editable_bytes", True))
    current_row = table.currentRow()
    table.blockSignals(True)
    table.setSortingEnabled(False)
    table.setRowCount(len(rows))
    selected_row = None
    highlight = QtGui.QColor("#c7ecc7")
    normal = QtGui.QColor("#ffffff")

    for row_index, row in enumerate(rows):
        values = [
            row.get("address") or "",
            row.get("bytes") or "",
            row.get("assembly") or "",
        ]
        for column, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(value)
            item.setFlags(_item_flags(QtCore, column == COL_ASSEMBLY or (editable_bytes and column == COL_BYTES)))
            item.setBackground(highlight if row.get("highlight") else normal)
            if column == COL_BYTES:
                item.setForeground(QtGui.QColor("#001dff"))
            if column == COL_ADDRESS and row.get("ea") is not None:
                item.setData(QtCore.Qt.UserRole, int(row.get("ea")))
            table.setItem(row_index, column, item)
        if row.get("highlight") and selected_row is None:
            selected_row = row_index

    table.resizeRowsToContents()
    table.blockSignals(False)
    target_row = current_row if 0 <= current_row < table.rowCount() else selected_row
    if target_row is not None and 0 <= target_row < table.rowCount():
        table.setCurrentCell(target_row, COL_ASSEMBLY)
        table.scrollToItem(table.item(target_row, COL_ADDRESS), QtWidgets.QAbstractItemView.PositionAtCenter)


def update_patch_table_preview(table, rows):
    """Update address/bytes values from preview rows while preserving assembly text."""
    QtCore, _QtGui, QtWidgets = load_qt()
    editable_bytes = bool(getattr(table, "_patch_table_editable_bytes", True))
    table.blockSignals(True)
    row_count = min(table.rowCount(), len(rows))
    for row_index in range(row_count):
        row = rows[row_index]
        address_item = table.item(row_index, COL_ADDRESS)
        bytes_item = table.item(row_index, COL_BYTES)
        if address_item is None:
            address_item = QtWidgets.QTableWidgetItem("")
            address_item.setFlags(_item_flags(QtCore, False))
            table.setItem(row_index, COL_ADDRESS, address_item)
        if bytes_item is None:
            bytes_item = QtWidgets.QTableWidgetItem("")
            bytes_item.setFlags(_item_flags(QtCore, editable_bytes))
            table.setItem(row_index, COL_BYTES, bytes_item)
        address_item.setText(row.get("address") or "")
        address_item.setData(
            QtCore.Qt.UserRole,
            int(row.get("ea")) if row.get("ea") is not None else None,
        )
        bytes_item.setText(row.get("bytes") or "")
    table.blockSignals(False)


def patch_table_assembly_text(table):
    """Return non-empty assembly rows from the editable table."""
    lines = []
    for row in range(table.rowCount()):
        item = table.item(row, COL_ASSEMBLY)
        text = item.text().strip() if item is not None else ""
        if text:
            lines.append(text)
    return "\n".join(lines)


def patch_table_bytes_blob(table):
    """Return concatenated bytes from the editable Bytes column."""
    data = bytearray()
    for row in range(table.rowCount()):
        item = table.item(row, COL_BYTES)
        text = item.text().strip() if item is not None else ""
        if not text:
            continue
        compact = text.replace(" ", "").replace("\t", "")
        if len(compact) % 2:
            raise ValueError("机器码必须是偶数个十六进制字符")
        try:
            data.extend(bytes.fromhex(compact))
        except ValueError as exc:
            raise ValueError("机器码只能包含十六进制字符和空格") from exc
    return bytes(data)


def patch_table_row_ea(table, row):
    """Return the EA stored/displayed for one table row."""
    QtCore, _QtGui, _QtWidgets = load_qt()
    item = table.item(row, COL_ADDRESS)
    if item is None:
        return None
    value = item.data(QtCore.Qt.UserRole)
    if value is not None:
        return int(value)
    text = item.text().strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def patch_table_row_byte_count(table, row):
    """Return the number of bytes represented by one Bytes cell."""
    item = table.item(row, COL_BYTES)
    text = item.text().strip() if item is not None else ""
    if not text or text == "(none)":
        return 0
    compact = text.replace(" ", "").replace("\t", "")
    if len(compact) % 2:
        return 0
    try:
        return len(bytes.fromhex(compact))
    except ValueError:
        return 0


def remove_selected_patch_rows(table):
    """Remove selected rows and return how many were removed."""
    rows = sorted({index.row() for index in table.selectedIndexes()}, reverse=True)
    if not rows and table.currentRow() >= 0:
        rows = [table.currentRow()]
    for row in rows:
        table.removeRow(row)
    return len(rows)


def insert_patch_row(table, row=None, assembly="nop", address="", bytes_value="", ea=None):
    """Insert one editable assembly row."""
    _QtCore, _QtGui, QtWidgets = load_qt()
    editable_bytes = bool(getattr(table, "_patch_table_editable_bytes", True))
    if row is None or row < 0:
        row = max(table.currentRow() + 1, table.rowCount())
    table.blockSignals(True)
    table.insertRow(row)
    for column, value in enumerate((address, bytes_value, assembly)):
        item = QtWidgets.QTableWidgetItem(value)
        item.setFlags(_item_flags(_QtCore, column == COL_ASSEMBLY or (editable_bytes and column == COL_BYTES)))
        if column == COL_BYTES:
            item.setForeground(_QtGui.QColor("#001dff"))
        if column == COL_ADDRESS and ea is not None:
            item.setData(_QtCore.Qt.UserRole, int(ea))
        table.setItem(row, column, item)
    table.blockSignals(False)
    table.setCurrentCell(row, COL_ASSEMBLY)
    table.editItem(table.item(row, COL_ASSEMBLY))
    return row


def bytes_text(data):
    """Return UI text for raw bytes."""
    return format_bytes_hex(data)
