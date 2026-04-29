"""Optional raw-byte disassembly helpers for UI previews."""

import idc


def _load_capstone():
    try:
        import capstone  # type: ignore

        return capstone
    except Exception:
        return None


def _x86_mode(capstone):
    is_64 = bool(idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT)
    return capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32


def disassemble_bytes(ea, raw_bytes, arch_key):
    """Return preview rows for raw bytes, or an empty list if unavailable."""
    capstone = _load_capstone()
    if capstone is None or not raw_bytes:
        return []

    little = getattr(capstone, "CS_MODE_LITTLE_ENDIAN", 0)
    try:
        if arch_key == "x86/x64":
            md = capstone.Cs(capstone.CS_ARCH_X86, _x86_mode(capstone))
        elif arch_key == "AArch64":
            md = capstone.Cs(capstone.CS_ARCH_ARM64, little)
        elif arch_key == "ARM/Thumb":
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | little)
        elif arch_key == "MIPS":
            md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | little)
        else:
            return []
    except Exception:
        return []

    rows = []
    consumed = 0
    for insn in md.disasm(raw_bytes, ea):
        if insn.address != ea + consumed:
            break
        text = insn.mnemonic
        if insn.op_str:
            text = "%s %s" % (text, insn.op_str)
        insn_bytes = bytes(insn.bytes)
        if not insn_bytes:
            break
        rows.append(
            {
                "ea": int(insn.address),
                "line": text,
                "bytes": insn_bytes,
                "note": "由 Bytes 列反汇编生成。",
            }
        )
        consumed += len(insn_bytes)

    while consumed < len(raw_bytes):
        value = raw_bytes[consumed]
        text = "db 0" if value == 0 else "db 0%02Xh" % value
        rows.append(
            {
                "ea": ea + consumed,
                "line": text,
                "bytes": bytes([value]),
                "note": "剩余字节按 data byte 显示。",
            }
        )
        consumed += 1

    return rows
