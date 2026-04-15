"""Assembly-pattern search helpers."""

import re

from ..ida_adapter import read_idb_bytes
from ..logging_utils import debug_log
from ..patching.ranges import iter_instruction_heads
from ..patching.selection import get_entries_for_line_count, join_entry_asm_lines
from .assemble import assemble_multiline
from .operands import processor_key, sanitize_asm_line, split_operands

SEARCH_MODE_EXACT = "exact"
SEARCH_MODE_TEXT = "text"
_SEARCH_TOKEN_RE = re.compile(r"^[a-z_.$?@][a-z0-9_.$?@]*$", re.IGNORECASE)


def _normalized_query_text(text):
    """Normalize a multiline assembly query into a stable instruction list."""
    lines = [sanitize_asm_line(line) for line in (text or "").splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        raise RuntimeError("请输入至少一条用于搜索的汇编指令。")
    return "\n".join(lines), len(lines)


def _normalized_query_lines(text):
    """Return normalized non-empty query lines."""
    return [line for line in (_normalized_query_text(text)[0]).splitlines() if line]


def _normalize_search_mode(mode):
    """Normalize one search mode string."""
    mode = (mode or SEARCH_MODE_EXACT).strip().lower()
    if mode not in (SEARCH_MODE_EXACT, SEARCH_MODE_TEXT):
        return SEARCH_MODE_EXACT
    return mode


def _entry_text_matches_query_line(query_line, entry):
    """Return whether one disassembly entry matches one text-search query line."""
    query = (query_line or "").strip().lower()
    if not query:
        return False

    asm_text = sanitize_asm_line(entry.get("asm") or entry.get("text") or "")
    disasm_text = sanitize_asm_line(entry.get("text") or entry.get("asm") or "")
    asm_lower = asm_text.lower()
    disasm_lower = disasm_text.lower()

    if _SEARCH_TOKEN_RE.match(query):
        mnem, operands = split_operands(asm_text)
        if (mnem or "").lower() == query:
            return True
        for operand in operands:
            operand = operand.strip().lower()
            if operand == query:
                return True
            if re.search(r"(?<![a-z0-9_.$?@])%s(?![a-z0-9_.$?@])" % re.escape(query), operand):
                return True
        return bool(
            re.search(r"(?<![a-z0-9_.$?@])%s(?![a-z0-9_.$?@])" % re.escape(query), asm_lower)
            or re.search(r"(?<![a-z0-9_.$?@])%s(?![a-z0-9_.$?@])" % re.escape(query), disasm_lower)
        )

    return query in asm_lower or query in disasm_lower


def _search_by_text(
    query_text,
    start_ea,
    end_ea,
    max_results,
    progress,
    progress_interval,
):
    """Search by mnemonic/register/free-text over disassembly lines."""
    query_lines = _normalized_query_lines(query_text)
    line_count = len(query_lines)

    def report_progress(current_ea, result_count, force=False):
        if progress is None:
            return
        if not force and scanned_count > 0 and (scanned_count % progress_interval) != 0:
            return
        keep_running = progress(
            {
                "start_ea": start_ea,
                "end_ea": end_ea,
                "current_ea": current_ea,
                "scanned_count": scanned_count,
                "result_count": result_count,
            }
        )
        if keep_running is False:
            raise RuntimeError("搜索已取消。")

    results = []
    scanned_count = 0
    report_progress(start_ea, 0, force=True)
    for ea in iter_instruction_heads(start_ea, end_ea, code_only=True):
        scanned_count += 1
        report_progress(ea, len(results))
        entries = get_entries_for_line_count(ea, line_count, log_events=False)
        if len(entries) < line_count:
            continue
        if not all(_entry_text_matches_query_line(query_line, entry) for query_line, entry in zip(query_lines, entries)):
            continue
        joined_bytes = b"".join(entry.get("bytes") or b"" for entry in entries)
        results.append(
            {
                "ea": ea,
                "size": len(joined_bytes),
                "bytes": joined_bytes,
                "notes": ["按助记符/寄存器/文本匹配。"],
                "line_infos": [],
                "disasm_text": join_entry_asm_lines(entries),
            }
        )
        report_progress(ea, len(results), force=True)
        if len(results) >= max_results:
            break

    report_progress(end_ea, len(results), force=True)
    return {
        "query_text": "\n".join(query_lines),
        "search_mode": SEARCH_MODE_TEXT,
        "start_ea": start_ea,
        "end_ea": end_ea,
        "scanned_count": scanned_count,
        "results": results,
        "result_count": len(results),
        "max_results": max_results,
    }


def _search_by_exact_assembly(
    query_text,
    start_ea,
    end_ea,
    arch_key,
    max_results,
    validation_entries,
    validation_ea,
    max_initial_failures,
    progress,
    progress_interval,
):
    """Search by exact assembled-byte equivalence."""
    line_count = len(_normalized_query_lines(query_text))

    if validation_entries:
        probe_entries = list(validation_entries)[:line_count]
        if probe_entries:
            probe_ea = (
                int(validation_ea)
                if validation_ea is not None
                else int(probe_entries[0].get("ea", start_ea))
            )
            try:
                assemble_multiline(
                    probe_ea,
                    query_text,
                    arch_key,
                    probe_entries,
                    log_events=False,
                )
            except Exception as exc:
                raise RuntimeError("搜索条件在当前上下文无法成功汇编: %s" % exc)

    def report_progress(current_ea, result_count, force=False):
        if progress is None:
            return
        if not force and scanned_count > 0 and (scanned_count % progress_interval) != 0:
            return
        keep_running = progress(
            {
                "start_ea": start_ea,
                "end_ea": end_ea,
                "current_ea": current_ea,
                "scanned_count": scanned_count,
                "result_count": result_count,
            }
        )
        if keep_running is False:
            raise RuntimeError("搜索已取消。")

    results = []
    first_error = None
    compiled_any = False
    scanned_count = 0
    failed_compiles = 0
    report_progress(start_ea, 0, force=True)
    for ea in iter_instruction_heads(start_ea, end_ea, code_only=True):
        scanned_count += 1
        report_progress(ea, len(results))
        original_entries = get_entries_for_line_count(ea, line_count, log_events=False)
        try:
            pattern_bytes, notes, line_infos = assemble_multiline(
                ea,
                query_text,
                arch_key,
                original_entries,
                log_events=False,
            )
            compiled_any = True
            failed_compiles = 0
        except Exception as exc:
            if first_error is None:
                first_error = exc
            failed_compiles += 1
            if not compiled_any and failed_compiles >= max_initial_failures:
                raise RuntimeError(
                    "搜索条件在当前范围前 %d 个候选位置都无法成功汇编: %s"
                    % (failed_compiles, first_error)
                )
            continue

        if not pattern_bytes or ea + len(pattern_bytes) > end_ea:
            continue
        if read_idb_bytes(ea, len(pattern_bytes)) != pattern_bytes:
            continue

        results.append(
            {
                "ea": ea,
                "size": len(pattern_bytes),
                "bytes": pattern_bytes,
                "notes": notes,
                "line_infos": line_infos,
                "disasm_text": join_entry_asm_lines(original_entries),
            }
        )
        report_progress(ea, len(results), force=True)
        if len(results) >= max_results:
            break

    if not compiled_any and first_error is not None:
        raise RuntimeError("搜索条件无法在当前范围内成功汇编: %s" % first_error)

    report_progress(end_ea, len(results), force=True)
    return {
        "query_text": query_text,
        "search_mode": SEARCH_MODE_EXACT,
        "arch_key": arch_key,
        "start_ea": start_ea,
        "end_ea": end_ea,
        "scanned_count": scanned_count,
        "results": results,
        "result_count": len(results),
        "max_results": max_results,
    }


def search_assembly(
    text,
    start_ea,
    end_ea,
    arch_key="",
    max_results=200,
    validation_entries=None,
    validation_ea=None,
    max_initial_failures=64,
    progress=None,
    progress_interval=64,
    mode=SEARCH_MODE_EXACT,
):
    """Search instruction heads where the given assembly query encodes to the current bytes."""
    if end_ea <= start_ea:
        raise RuntimeError("搜索范围无效：结束地址必须大于起始地址。")

    query_text, _line_count = _normalized_query_text(text)
    mode = _normalize_search_mode(mode)
    arch_key = arch_key or processor_key()
    max_results = max(1, int(max_results or 1))
    max_initial_failures = max(1, int(max_initial_failures or 1))
    progress_interval = max(1, int(progress_interval or 1))
    if mode == SEARCH_MODE_TEXT:
        result = _search_by_text(
            query_text,
            start_ea,
            end_ea,
            max_results,
            progress,
            progress_interval,
        )
    else:
        result = _search_by_exact_assembly(
            query_text,
            start_ea,
            end_ea,
            arch_key,
            max_results,
            validation_entries,
            validation_ea,
            max_initial_failures,
            progress,
            progress_interval,
        )
    debug_log(
        "assembly_search.complete",
        start_ea="0x%X" % start_ea,
        end_ea="0x%X" % end_ea,
        scanned_count=result["scanned_count"],
        result_count=result["result_count"],
        search_mode=mode,
        query=query_text,
    )
    return result
