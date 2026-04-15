"""Prompt helpers for oversized inline assembly patches."""

from ..patching.overflow_policy import (
    ASSEMBLE_OVERSIZE_INLINE,
    ASSEMBLE_OVERSIZE_TRAMPOLINE,
)
from .common import load_qt


def prompt_oversize_patch_choice(parent, plan, has_selection):
    """Ask how to handle an oversized inline patch and whether to remember the choice."""
    _QtCore, _QtGui, QtWidgets = load_qt()
    overflow_size = int(plan.get("overflow_size") or 0)
    effective_end_ea = int(plan.get("effective_end_ea") or 0)
    assembled_size = len(plan.get("assembled_bytes") or b"")
    requested_region_size = int(plan.get("requested_region_size") or 0)
    effective_region_size = int(plan.get("effective_region_size") or requested_region_size)
    tail_nop_size = len(plan.get("tail_nop_bytes") or b"")
    can_inline = not has_selection and not plan.get("exceeds_selection")

    box = QtWidgets.QMessageBox(parent)
    box.setIcon(QtWidgets.QMessageBox.Warning)
    box.setWindowTitle("汇编长度超出原范围")
    if can_inline:
        box.setText(
            "新汇编为 %d bytes，已超出当前指令范围 %d bytes。"
            % (assembled_size, overflow_size)
        )
        detail = [
            "如果继续覆盖，插件会按完整指令边界写到 0x%X。"
            % (effective_end_ea - 1),
        ]
        if tail_nop_size:
            detail.append("边界扩展后剩余 %d bytes 会自动补 NOP。" % tail_nop_size)
        detail.append("也可以直接改用代码注入，把新逻辑放到代码洞里。")
    else:
        box.setText(
            "新汇编为 %d bytes，已超出当前可覆盖范围 %d bytes。"
            % (assembled_size, overflow_size)
        )
        detail = [
            "当前选区只有 %d bytes，不能直接把这段汇编写进去。" % requested_region_size,
            "你可以取消后扩大选区，或者直接改用代码注入。",
        ]
        if effective_region_size > requested_region_size:
            detail.append("按完整指令边界估算，至少会写到 0x%X。" % (effective_end_ea - 1))
    box.setInformativeText("\n".join(detail))

    remember = QtWidgets.QCheckBox("记住这次选择，后续遇到超长时直接按这个处理", box)
    box.setCheckBox(remember)

    inline_btn = None
    if can_inline:
        inline_btn = box.addButton("继续覆盖", QtWidgets.QMessageBox.AcceptRole)
    trampoline_btn = box.addButton("改用代码注入", QtWidgets.QMessageBox.ActionRole)
    cancel_btn = box.addButton("取消", QtWidgets.QMessageBox.RejectRole)
    box.setDefaultButton(trampoline_btn if not can_inline else inline_btn)
    box.exec()

    clicked = box.clickedButton()
    if clicked == inline_btn:
        return ASSEMBLE_OVERSIZE_INLINE, bool(remember.isChecked())
    if clicked == trampoline_btn:
        return ASSEMBLE_OVERSIZE_TRAMPOLINE, bool(remember.isChecked())
    return None, False
