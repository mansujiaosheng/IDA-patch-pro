"""Shared Qt loading and modeless dialog helpers."""

_MODELLESS_DIALOGS = []


def load_qt():
    """Import PySide6 lazily so the package loads cleanly inside IDA."""
    from PySide6 import QtCore, QtGui, QtWidgets

    return QtCore, QtGui, QtWidgets


def show_modeless_dialog(owner):
    """Show a dialog modelessly and keep the wrapper object alive until close."""
    QtCore, _, _ = load_qt()
    dialog = owner.dialog
    dialog.setModal(False)
    dialog.setWindowModality(QtCore.Qt.NonModal)
    dialog.setAttribute(QtCore.Qt.WA_DeleteOnClose, True)

    if owner not in _MODELLESS_DIALOGS:
        _MODELLESS_DIALOGS.append(owner)

    def cleanup(*_args):
        try:
            _MODELLESS_DIALOGS.remove(owner)
        except ValueError:
            pass

    try:
        dialog.finished.connect(cleanup)
    except Exception:
        pass
    try:
        dialog.destroyed.connect(cleanup)
    except Exception:
        pass

    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
    return 1
