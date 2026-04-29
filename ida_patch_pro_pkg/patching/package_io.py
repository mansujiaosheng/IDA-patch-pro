# -*- coding: utf-8 -*-
"""
Patch package export/import for ida_patch_pro.

说明：
- 导出时从现有补丁历史里取 status=active 的事务
- 优先导出事务里记录的 input_file_before 作为“原始基线文件”
- 同时记录导出时目标文件最终状态 `expected_final_input_file`
- 导入时允许当前文件匹配 baseline_input_file 或 expected_final_input_file
- 对 write_to_file=True 的操作，优先按照 file_chunks 的 offset/old_bytes 校验并写回文件
- 同时把补丁同步应用到 IDB，并写入新的事务历史，便于继续回撤
"""

import hashlib
import json
import os
import time

import ida_auto
import ida_bytes
import ida_kernwin

from ..backends.elf_backend import elf_patch_segment_info, prepare_elf_patch_segment
from ..backends.pe_backend import pe_patch_section_info, prepare_file_patch_segment
from ..constants import PATCH_FILE_SECTION_NAME, PATCH_STUB_ALIGN, PLUGIN_NAME
from ..ida_adapter import (
    current_database_identity,
    current_database_label,
    current_imagebase,
    input_file_path,
    read_idb_bytes,
)
from ..logging_utils import debug_log_exception
from ..patching.selection import get_entries_for_range
from ..trampoline.apply import apply_trampoline_patch
from ..trampoline.file_storage import BINARY_KIND_ELF, BINARY_KIND_PE, input_binary_kind
from ..trampoline.planner import preview_trampoline_plan
from .history_store import load_patch_history
from .rollback import rollback_partial_transaction
from .transactions import (
    begin_patch_transaction,
    commit_patch_transaction,
    record_transaction_operation,
    resolve_operation_ea,
)

PATCH_PACKAGE_MAGIC = "ida_patch_pro.package"
PATCH_PACKAGE_VERSION = 1
PATCH_PACKAGE_SUFFIX = ".idppatch.json"


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _safe_basename(path):
    try:
        return os.path.basename(path)
    except Exception:
        return ""


def _default_export_path():
    input_path = input_file_path() or ""
    base = _safe_basename(input_path) or "patch_package"
    return base + PATCH_PACKAGE_SUFFIX


def _ask_export_path():
    default_name = _default_export_path()
    path = ida_kernwin.ask_file(
        True,
        "*" + PATCH_PACKAGE_SUFFIX,
        "导出补丁包 (%s)" % default_name,
    )
    if not path:
        return ""
    if not path.lower().endswith(PATCH_PACKAGE_SUFFIX):
        path += PATCH_PACKAGE_SUFFIX
    return path


def _ask_import_path():
    path = ida_kernwin.ask_file(
        False,
        "*" + PATCH_PACKAGE_SUFFIX,
        "导入补丁包",
    )
    return path or ""


def _current_input_file_info():
    path = input_file_path() or ""
    info = {
        "path": path,
        "name": _safe_basename(path),
        "size": None,
        "sha256": None,
    }
    if not path or not os.path.isfile(path):
        return info
    try:
        info["size"] = os.path.getsize(path)
    except Exception:
        info["size"] = None
    try:
        info["sha256"] = _sha256_file(path)
    except Exception:
        info["sha256"] = None
    return info


def _entry_is_exportable(entry):
    if not isinstance(entry, dict):
        return False
    if (entry.get("status") or "").lower() != "active":
        return False
    if (entry.get("kind") or "").lower() == "import_package":
        return False
    ops = entry.get("ops") or []
    return bool(ops)


def _normalize_export_op(entry, op):
    """
    把历史里的 operation 转成稳定导出格式。
    """
    meta = entry.get("meta") or {}
    ea = resolve_operation_ea(op, meta)
    size = int(op.get("size") or 0)
    old_hex = (op.get("old_bytes_hex") or "").lower()
    new_hex = (op.get("new_bytes_hex") or "").lower()
    note = op.get("note") or ""
    patch_mode = op.get("patch_mode") or "code"

    if ea is None:
        raise RuntimeError("发现无法解析 EA 的补丁操作。")
    if size <= 0:
        raise RuntimeError("发现 size <= 0 的补丁操作。")
    if not new_hex:
        raise RuntimeError("发现缺少 new_bytes_hex 的补丁操作。")
    if not old_hex:
        raise RuntimeError("发现缺少 old_bytes_hex 的补丁操作，无法安全导出。")

    exported_chunks = []
    for chunk in op.get("file_chunks") or []:
        exported_chunks.append(
            {
                "offset": int(chunk.get("offset") or 0),
                "old_bytes_hex": (chunk.get("old_bytes_hex") or "").lower(),
                "new_bytes_hex": (chunk.get("new_bytes_hex") or "").lower(),
            }
        )

    return {
        "ea": int(ea),
        "imagebase": int(op.get("imagebase") or meta.get("imagebase") or 0),
        "segment_name": op.get("segment_name") or "",
        "segment_offset": int(op.get("segment_offset") or 0),
        "size": size,
        "old_bytes_hex": old_hex,
        "new_bytes_hex": new_hex,
        "note": note,
        "patch_mode": patch_mode,
        "write_to_file": bool(op.get("write_to_file")),
        "file_path": op.get("file_path") or "",
        "file_chunks": exported_chunks,
    }


def _collect_export_transactions():
    entries = load_patch_history()
    out = []
    for entry in entries:
        if not _entry_is_exportable(entry):
            continue
        ops = entry.get("ops") or []
        normalized_ops = []
        for op in ops:
            normalized_ops.append(_normalize_export_op(entry, op))
        out.append(
            {
                "tx_id": entry.get("tx_id"),
                "kind": entry.get("kind") or "",
                "label": entry.get("label") or entry.get("kind") or "patch",
                "target_ea": int(entry.get("target_ea") or 0),
                "created_at": entry.get("created_at"),
                "meta": {
                    "imagebase": int((entry.get("meta") or {}).get("imagebase") or 0),
                    "write_to_file": bool((entry.get("meta") or {}).get("write_to_file")),
                    "input_file_before": (entry.get("meta") or {}).get("input_file_before"),
                    "input_file_after": (entry.get("meta") or {}).get("input_file_after"),
                    "trampoline_replay": (entry.get("meta") or {}).get("trampoline_replay"),
                },
                "ops": normalized_ops,
            }
        )
    return out


def _pick_baseline_input_file(transactions):
    for tx in transactions:
        meta = tx.get("meta") or {}
        baseline = meta.get("input_file_before")
        if baseline:
            return baseline
    return None


def _pick_expected_final_input_file(transactions):
    for tx in reversed(transactions):
        meta = tx.get("meta") or {}
        final_info = meta.get("input_file_after")
        if final_info:
            return final_info
    return None


def _build_export_package(transactions):
    current_input_info = _current_input_file_info()
    baseline_input_info = _pick_baseline_input_file(transactions) or current_input_info
    expected_final_input_info = _pick_expected_final_input_file(transactions) or current_input_info

    return {
        "magic": PATCH_PACKAGE_MAGIC,
        "version": PATCH_PACKAGE_VERSION,
        "plugin": PLUGIN_NAME,
        "created_at": int(time.time()),
        "database": {
            "label": current_database_label(),
            "identity": current_database_identity(),
            "imagebase": int(current_imagebase() or 0),
        },
        "baseline_input_file": baseline_input_info,
        "expected_final_input_file": expected_final_input_info,
        "exporter_current_input_file": current_input_info,
        "transactions": transactions,
    }


def export_patch_package_via_dialog():
    try:
        txs = _collect_export_transactions()
        if not txs:
            ida_kernwin.warning("当前没有可导出的 active 补丁事务。")
            return False

        path = _ask_export_path()
        if not path:
            return False

        package = _build_export_package(txs)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(package, fh, ensure_ascii=False, indent=2)

        ida_kernwin.info(
            "补丁包导出成功。\n\n"
            "文件: %s\n"
            "事务数: %d\n"
            "操作数: %d"
            % (
                path,
                len(package["transactions"]),
                sum(len(tx.get("ops") or []) for tx in package["transactions"]),
            )
        )
        return True
    except Exception as exc:
        debug_log_exception("patch_package.export.failure", exc)
        ida_kernwin.warning("导出补丁包失败：\n%s" % exc)
        return False


def _load_package_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise RuntimeError("补丁包 JSON 顶层必须是对象。")
    if data.get("magic") != PATCH_PACKAGE_MAGIC:
        raise RuntimeError("不是 ida_patch_pro 的补丁包文件。")
    if int(data.get("version") or 0) != PATCH_PACKAGE_VERSION:
        raise RuntimeError(
            "不支持的补丁包版本：%r（当前仅支持 %d）"
            % (data.get("version"), PATCH_PACKAGE_VERSION)
        )
    txs = data.get("transactions")
    if not isinstance(txs, list) or not txs:
        raise RuntimeError("补丁包里没有可导入的 transactions。")
    return data


def _select_import_transactions(pkg):
    txs = [
        tx
        for tx in (pkg.get("transactions") or [])
        if isinstance(tx, dict) and (tx.get("ops") or [])
    ]
    primary = [tx for tx in txs if (tx.get("kind") or "").lower() != "import_package"]
    return primary or txs


def _package_target_ea(pkg_ea, package_imagebase):
    """
    导出包里保存的是导出时的绝对 EA。
    如果导入时当前 IDB imagebase 不同，则按 delta 重定位。
    """
    cur_base = int(current_imagebase() or 0)
    old_base = int(package_imagebase or 0)
    ea = int(pkg_ea or 0)
    if old_base and cur_base and old_base != cur_base:
        return ea - old_base + cur_base
    return ea


def _patch_idb_bytes(ea, data):
    if not data:
        return
    patch_bytes = getattr(ida_bytes, "patch_bytes", None)
    if patch_bytes is not None:
        ok = patch_bytes(ea, data)
        if ok is False:
            raise RuntimeError("ida_bytes.patch_bytes 返回失败，EA=0x%X" % ea)
        return
    patch_byte = getattr(ida_bytes, "patch_byte", None)
    if patch_byte is None:
        raise RuntimeError("当前 IDA 没有可用的 patch_bytes/patch_byte API。")
    for i, b in enumerate(data):
        patch_byte(ea + i, b)


def _verify_input_file_match(pkg):
    pkg_input = (
        pkg.get("baseline_input_file")
        or pkg.get("input_file")
        or {}
    )
    pkg_expected_final = (
        pkg.get("expected_final_input_file")
        or pkg.get("exporter_current_input_file")
        or {}
    )
    cur_input = _current_input_file_info()

    pkg_name = pkg_input.get("name") or ""
    pkg_size = pkg_input.get("size")
    pkg_sha256 = pkg_input.get("sha256") or ""
    pkg_final_name = pkg_expected_final.get("name") or ""
    pkg_final_size = pkg_expected_final.get("size")
    pkg_final_sha256 = pkg_expected_final.get("sha256") or ""

    cur_name = cur_input.get("name") or ""
    cur_size = cur_input.get("size")
    cur_sha256 = cur_input.get("sha256") or ""

    if pkg_sha256 and cur_sha256:
        if pkg_sha256 == cur_sha256:
            return True
        if pkg_final_sha256 and pkg_final_sha256 == cur_sha256:
            return True
        choice = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "补丁包记录的原始/目标文件 SHA256 都与当前输入文件不一致。\n\n"
            "补丁包基线文件: %s\n"
            "补丁包目标文件: %s\n"
            "当前文件: %s\n"
            "补丁包基线大小: %s\n"
            "补丁包目标大小: %s\n"
            "当前大小: %s\n\n"
            "期望当前文件要么等于导出前原始文件，要么已经等于导出后的目标文件。\n"
            "仍要继续尝试导入吗？"
            % (pkg_name, pkg_final_name, cur_name, pkg_size, pkg_final_size, cur_size)
        )
        return choice == ida_kernwin.ASKBTN_YES

    if pkg_name and cur_name and pkg_name == cur_name and pkg_size == cur_size:
        return True
    if pkg_final_name and cur_name and pkg_final_name == cur_name and pkg_final_size == cur_size:
        return True

    choice = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_NO,
        "无法严格确认当前输入文件与补丁包记录的原始/目标文件一致。\n\n"
        "补丁包基线文件: %s\n"
        "补丁包目标文件: %s\n"
        "当前文件: %s\n"
        "补丁包基线大小: %s\n"
        "补丁包目标大小: %s\n"
        "当前大小: %s\n\n"
        "仍要继续尝试导入吗？"
        % (pkg_name, pkg_final_name, cur_name, pkg_size, pkg_final_size, cur_size)
    )
    return choice == ida_kernwin.ASKBTN_YES


def _read_file_chunk(path, offset, size):
    with open(path, "rb") as fh:
        fh.seek(offset)
        return fh.read(size)


def _write_file_chunk(path, offset, data):
    with open(path, "r+b") as fh:
        fh.seek(offset)
        fh.write(data)


def _file_backed_required_size(target_ea, payload_size, info):
    """Estimate the section size required to cover one imported file-backed EA."""
    base_ea = int((info or {}).get("ea_start") or target_ea)
    if target_ea < base_ea:
        return payload_size + PATCH_STUB_ALIGN
    return (target_ea - base_ea) + payload_size + PATCH_STUB_ALIGN


def _ensure_file_backed_import_mapping(op, target_ea, new_bytes):
    """Ensure one imported file-backed cave is mapped into the current IDB."""
    if (op.get("segment_name") or "") != PATCH_FILE_SECTION_NAME:
        return

    binary_kind = input_binary_kind()
    if binary_kind == BINARY_KIND_PE:
        info = pe_patch_section_info(0)
        required_size = _file_backed_required_size(target_ea, len(new_bytes), info)
        prepare_file_patch_segment(required_size, apply_changes=True)
        return

    if binary_kind == BINARY_KIND_ELF:
        info = elf_patch_segment_info(0)
        required_size = _file_backed_required_size(target_ea, len(new_bytes), info)
        prepare_elf_patch_segment(required_size, apply_changes=True)
        return


def _patch_file_segment_range(binary_kind, payload_size):
    if binary_kind == BINARY_KIND_PE:
        info = pe_patch_section_info(payload_size)
        return int(info.get("ea_start") or 0), int(info.get("raw_size") or 0)
    if binary_kind == BINARY_KIND_ELF:
        info = elf_patch_segment_info(payload_size)
        return int(info.get("ea_start") or 0), int(info.get("raw_size") or 0)
    return 0, 0


def _looks_like_legacy_file_backed_cave(op, target_ea, payload_size):
    if (op.get("segment_name") or "") == PATCH_FILE_SECTION_NAME:
        return True
    if bool(op.get("write_to_file")) or (op.get("file_chunks") or []):
        return False

    binary_kind = input_binary_kind()
    ea_start, raw_size = _patch_file_segment_range(binary_kind, payload_size)
    if ea_start <= 0 or raw_size <= 0:
        return False
    return ea_start <= int(target_ea) < (ea_start + raw_size)


def _prepare_legacy_file_backed_import(op, target_ea, new_bytes):
    if not _looks_like_legacy_file_backed_cave(op, target_ea, len(new_bytes)):
        return False
    file_backed_op = dict(op)
    file_backed_op["segment_name"] = PATCH_FILE_SECTION_NAME
    _ensure_file_backed_import_mapping(file_backed_op, target_ea, new_bytes)
    return True


def _find_tx_operation(tx, note_suffix):
    for op in tx.get("ops") or []:
        note = (op.get("note") or "").lower()
        if note.endswith(note_suffix):
            return op
    return None


def _replay_original_entries(replay, package_imagebase):
    entries = []
    for item in replay.get("original_entries") or []:
        if not isinstance(item, dict):
            continue
        entries.append(
            {
                "ea": _package_target_ea(item.get("ea"), package_imagebase),
                "text": item.get("text") or "",
                "asm": item.get("asm") or "",
                "bytes": bytes.fromhex((item.get("bytes_hex") or "").strip()),
                "operand_infos": list(item.get("operand_infos") or []),
            }
        )
    return entries


def _import_trampoline_transaction_via_replay(pkg, tx, package_imagebase):
    replay = ((tx.get("meta") or {}).get("trampoline_replay") or {})
    if not replay:
        return None

    start_ea = _package_target_ea(
        tx.get("target_ea") or ((tx.get("ops") or [{}])[0].get("ea") or 0),
        package_imagebase,
    )
    region_size = int(replay.get("region_size") or (tx.get("meta") or {}).get("region_size") or 0)
    if start_ea <= 0 or region_size <= 0:
        return None

    custom_text = replay.get("custom_text") or ""
    include_original = bool(replay.get("include_original"))
    write_to_file = bool(replay.get("write_to_file"))

    cave_op = _find_tx_operation(tx, "trampoline_cave")
    entry_op = _find_tx_operation(tx, "trampoline_entry")
    if cave_op and entry_op:
        cave_ea = _package_target_ea(cave_op.get("ea"), package_imagebase)
        cave_new = bytes.fromhex((cave_op.get("new_bytes_hex") or "").strip())
        entry_new = bytes.fromhex((entry_op.get("new_bytes_hex") or "").strip())
        current_cave = read_idb_bytes(cave_ea, len(cave_new))
        current_entry = read_idb_bytes(start_ea, len(entry_new))
        if current_cave == cave_new and current_entry == entry_new:
            return 0

    original_entries = _replay_original_entries(replay, package_imagebase)
    if not original_entries:
        original_entries = get_entries_for_range(start_ea, region_size, log_events=False)

    def plan_builder():
        return preview_trampoline_plan(
            start_ea,
            region_size,
            custom_text,
            original_entries,
            include_original,
            write_to_file=write_to_file,
        )

    plan = plan_builder()
    apply_trampoline_patch(
        start_ea,
        region_size,
        plan,
        trace_id="import_package-0x%X" % start_ea,
        plan_builder=plan_builder,
        transaction_kind="import_package",
        transaction_label="导入补丁包",
        transaction_meta={
            "package_created_at": pkg.get("created_at"),
            "package_tx_id": tx.get("tx_id"),
            "package_label": tx.get("label"),
            "package_kind": tx.get("kind"),
            "package_input_name": (
                pkg.get("baseline_input_file") or {}
            ).get("name"),
            "trampoline_replay": replay,
        },
    )
    return 2


def _import_one_transaction(pkg, tx):
    pkg_db = pkg.get("database") or {}
    package_imagebase = int(pkg_db.get("imagebase") or 0)

    ops = tx.get("ops") or []
    if not ops:
        return 0

    if (tx.get("kind") or "").lower() == "trampoline":
        replay_result = _import_trampoline_transaction_via_replay(pkg, tx, package_imagebase)
        if replay_result is not None:
            return replay_result

    first_target_ea = _package_target_ea(
        tx.get("target_ea") or ops[0].get("ea"),
        package_imagebase,
    )

    transaction = begin_patch_transaction(
        "import_package",
        "导入补丁包",
        first_target_ea,
        meta={
            "imagebase": int(current_imagebase() or 0),
            "package_created_at": pkg.get("created_at"),
            "package_tx_id": tx.get("tx_id"),
            "package_label": tx.get("label"),
            "package_kind": tx.get("kind"),
            "package_input_name": (
                pkg.get("baseline_input_file") or {}
            ).get("name"),
        },
    )

    applied_count = 0
    try:
        current_input = _current_input_file_info()
        current_file_path = current_input.get("path") or ""

        for op in ops:
            target_ea = _package_target_ea(op.get("ea"), package_imagebase)
            old_bytes = bytes.fromhex((op.get("old_bytes_hex") or "").strip())
            new_bytes = bytes.fromhex((op.get("new_bytes_hex") or "").strip())
            patch_mode = op.get("patch_mode") or "code"

            if len(old_bytes) != int(op.get("size") or 0):
                raise RuntimeError(
                    "old_bytes_hex 长度与 size 不一致，EA=0x%X" % target_ea
                )
            if len(new_bytes) != int(op.get("size") or 0):
                raise RuntimeError(
                    "new_bytes_hex 长度与 size 不一致，EA=0x%X" % target_ea
                )

            file_chunks = op.get("file_chunks") or []
            write_to_file = bool(op.get("write_to_file")) and bool(file_chunks) and bool(current_file_path)

            # 情况 1：这是文件补丁。以文件为准，IDB 仅 best-effort 同步
            if write_to_file:
                _ensure_file_backed_import_mapping(op, target_ea, new_bytes)
                need_apply_file = False

                for chunk in file_chunks:
                    offset = int(chunk.get("offset") or 0)
                    chunk_old = bytes.fromhex((chunk.get("old_bytes_hex") or "").strip())
                    chunk_new = bytes.fromhex((chunk.get("new_bytes_hex") or "").strip())
                    current_chunk = _read_file_chunk(current_file_path, offset, len(chunk_old))

                    if current_chunk == chunk_old:
                        need_apply_file = True
                        continue

                    if current_chunk == chunk_new:
                        # 已经是目标状态，这块跳过
                        continue

                    raise RuntimeError(
                        "导入前文件校验失败：文件偏移 0x%X 处当前字节既不是 old_bytes 也不是 new_bytes。\n"
                        "当前: %s\n"
                        "期望 old: %s\n"
                        "期望 new: %s"
                        % (offset, current_chunk.hex(), chunk_old.hex(), chunk_new.hex())
                    )

                # 只有真的要应用时才记录事务
                if need_apply_file:
                    record_transaction_operation(
                        transaction,
                        target_ea,
                        new_bytes,
                        write_to_file=True,
                        note="import_package:%s" % (op.get("note") or ""),
                        patch_mode=patch_mode,
                    )

                    for chunk in file_chunks:
                        offset = int(chunk.get("offset") or 0)
                        chunk_new = bytes.fromhex((chunk.get("new_bytes_hex") or "").strip())
                        current_chunk = _read_file_chunk(current_file_path, offset, len(chunk_new))
                        if current_chunk != chunk_new:
                            _write_file_chunk(current_file_path, offset, chunk_new)

                    applied_count += 1

                _ensure_file_backed_import_mapping(op, target_ea, new_bytes)

                # 无论文件是否需要应用，都尝试把 IDB 同步到 new_bytes
                # 这里不再把 IDB 不匹配当成致命错误
                try:
                    current_idb = read_idb_bytes(target_ea, len(new_bytes))
                    if current_idb != new_bytes:
                        _patch_idb_bytes(target_ea, new_bytes)
                except Exception:
                    # 某些地址可能不适合直接按 EA 同步到 IDB，忽略即可
                    pass

                continue

            # 情况 2：纯 IDB 补丁，仍然保持严格校验
            legacy_file_backed = _prepare_legacy_file_backed_import(op, target_ea, new_bytes)
            current = read_idb_bytes(target_ea, len(old_bytes))
            if current == old_bytes:
                record_transaction_operation(
                    transaction,
                    target_ea,
                    new_bytes,
                    write_to_file=False,
                    note="import_package:%s" % (op.get("note") or ""),
                    patch_mode=patch_mode,
                )
                _patch_idb_bytes(target_ea, new_bytes)
                applied_count += 1
                continue

            if legacy_file_backed and current == (b"\xFF" * len(old_bytes)):
                record_transaction_operation(
                    transaction,
                    target_ea,
                    new_bytes,
                    write_to_file=False,
                    note="import_package_legacy_file_backed:%s" % (op.get("note") or ""),
                    patch_mode=patch_mode,
                )
                _patch_idb_bytes(target_ea, new_bytes)
                applied_count += 1
                continue

            if current == new_bytes:
                # 已经打过这个补丁
                continue

            raise RuntimeError(
                "导入前校验失败：EA=0x%X 处当前字节既不是 old_bytes 也不是 new_bytes。\n"
                "当前: %s\n"
                "期望 old: %s\n"
                "期望 new: %s"
                % (target_ea, current.hex(), old_bytes.hex(), new_bytes.hex())
            )

        if applied_count > 0:
            commit_patch_transaction(transaction)

        return applied_count
    except Exception:
        rollback_partial_transaction(transaction, applied_count)
        raise

def import_patch_package_via_dialog():
    try:
        path = _ask_import_path()
        if not path:
            return False

        pkg = _load_package_file(path)

        if not _verify_input_file_match(pkg):
            ida_kernwin.warning("已取消导入。")
            return False

        selected_txs = _select_import_transactions(pkg)
        if not selected_txs:
            raise RuntimeError("补丁包里没有可导入的有效事务。")

        total_tx = 0
        total_ops = 0
        for tx in selected_txs:
            total_ops += _import_one_transaction(pkg, tx)
            total_tx += 1

        ida_auto.auto_wait()

        ida_kernwin.info(
            "补丁包导入成功。\n\n"
            "文件: %s\n"
            "导入事务数: %d\n"
            "导入操作数: %d"
            % (path, total_tx, total_ops)
        )
        return True
    except Exception as exc:
        debug_log_exception("patch_package.import.failure", exc)
        ida_kernwin.warning("导入补丁包失败：\n%s" % exc)
        return False
