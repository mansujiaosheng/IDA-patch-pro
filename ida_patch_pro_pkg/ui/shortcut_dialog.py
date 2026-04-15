"""Shortcut settings dialog."""

import ida_kernwin

from ..constants import ACTION_SHORTCUT_SPECS, PLUGIN_NAME
from ..patching.history_store import (
    apply_registered_shortcuts,
    default_action_shortcuts,
    load_action_shortcuts,
    normalize_shortcut_text,
    save_action_shortcuts,
)
from .common import load_qt, show_modeless_dialog


class ShortcutSettingsDialog:
    """Edit and persist plugin action shortcuts."""

    def __init__(self, parent=None):
        """Build the shortcut settings dialog."""
        _QtCore, _QtGui, QtWidgets = load_qt()
        self.dialog = QtWidgets.QDialog(parent)
        self.dialog.setWindowTitle("快捷键设置")
        self.dialog.resize(640, 320)
        self._edits = {}
        self._defaults = default_action_shortcuts()

        root = QtWidgets.QVBoxLayout(self.dialog)

        note = QtWidgets.QLabel(
            "修改后会保存到本地设置文件，并尽量立即更新到当前 IDA 会话。"
            " 留空表示不为该动作设置快捷键。",
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        form = QtWidgets.QFormLayout()
        current = load_action_shortcuts()
        for action_name, label, default_shortcut in ACTION_SHORTCUT_SPECS:
            edit = QtWidgets.QLineEdit(self.dialog)
            edit.setPlaceholderText(default_shortcut or "例如: Ctrl+Alt+A")
            edit.setText(current.get(action_name) or "")
            form.addRow("%s:" % label, edit)
            self._edits[action_name] = edit
        root.addLayout(form)

        self.status = QtWidgets.QLabel("", self.dialog)
        root.addWidget(self.status)

        toolbar = QtWidgets.QHBoxLayout()
        self.reset_btn = QtWidgets.QPushButton("恢复默认", self.dialog)
        self.reset_btn.clicked.connect(self._reset_defaults)
        toolbar.addWidget(self.reset_btn)

        toolbar.addStretch(1)

        self.save_btn = QtWidgets.QPushButton("保存", self.dialog)
        self.save_btn.clicked.connect(self._save)
        toolbar.addWidget(self.save_btn)

        self.close_btn = QtWidgets.QPushButton("关闭", self.dialog)
        self.close_btn.clicked.connect(self.dialog.close)
        toolbar.addWidget(self.close_btn)
        root.addLayout(toolbar)

    def _collect_shortcuts(self):
        """Collect normalized shortcut strings from the line edits."""
        return {
            action_name: normalize_shortcut_text(edit.text())
            for action_name, edit in self._edits.items()
        }

    def _reset_defaults(self):
        """Reset all editable shortcuts to the built-in defaults."""
        for action_name, edit in self._edits.items():
            edit.setText(self._defaults.get(action_name) or "")
        self.status.setText("已恢复默认快捷键，点击“保存”后生效。")

    def _save(self):
        """Save current shortcuts and apply them to the running session when possible."""
        shortcuts = self._collect_shortcuts()
        save_action_shortcuts(shortcuts)
        applied = apply_registered_shortcuts(shortcuts)
        if applied:
            self.status.setText("快捷键已保存，并已立即应用到当前 IDA 会话。")
        else:
            self.status.setText("快捷键已保存。若当前会话未立即更新，重载插件后生效。")
        ida_kernwin.msg("[%s] 快捷键设置已保存。\n" % PLUGIN_NAME)

    def exec(self):
        """Show the shortcut settings dialog modelessly."""
        return show_modeless_dialog(self)
