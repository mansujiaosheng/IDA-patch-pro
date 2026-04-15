"""Attach trampoline caves to the owning function and clean them up on rollback."""

import ida_funcs
import idc

from ..ida_adapter import rebase_history_ea, transaction_imagebase
from ..logging_utils import debug_log


def attach_cave_to_owner_function(owner_ea, cave_start, cave_end):
    """Treat the cave as a tail chunk of the original function instead of a fake callee."""
    owner = ida_funcs.get_func(owner_ea)
    if owner is None:
        return False

    existing = ida_funcs.get_func(cave_start)
    if existing is not None and existing.start_ea == cave_start:
        ida_funcs.del_func(cave_start)

    if not ida_funcs.append_func_tail(owner, cave_start, cave_end):
        chunk = ida_funcs.get_fchunk(cave_start)
        if chunk is None or chunk.start_ea != cave_start or chunk.end_ea != cave_end:
            return False

    ida_funcs.reanalyze_function(owner)
    debug_log(
        "trampoline.attach_tail",
        owner="0x%X" % owner.start_ea,
        cave_start="0x%X" % cave_start,
        cave_end="0x%X" % cave_end,
    )
    return True


def cleanup_trampoline_tail(meta):
    """Best-effort cleanup for a trampoline cave that had been attached as a tail chunk."""
    stored_imagebase = transaction_imagebase(meta)
    cave_start = rebase_history_ea(meta.get("cave_start"), stored_imagebase)
    owner_ea = rebase_history_ea(meta.get("owner_ea") or meta.get("start_ea"), stored_imagebase)
    if cave_start is None or owner_ea is None:
        return

    owner = ida_funcs.get_func(owner_ea)
    if owner is not None and hasattr(ida_funcs, "remove_func_tail"):
        try:
            ida_funcs.remove_func_tail(owner, cave_start)
        except TypeError:
            try:
                chunk = ida_funcs.get_fchunk(cave_start)
                if chunk is not None:
                    ida_funcs.remove_func_tail(owner, chunk)
            except Exception:
                pass
        except Exception:
            pass

    existing = ida_funcs.get_func(cave_start)
    if existing is not None and existing.start_ea == cave_start:
        try:
            ida_funcs.del_func(cave_start)
        except Exception:
            pass

    try:
        idc.set_name(cave_start, "", idc.SN_NOWARN)
    except Exception:
        pass

    if owner is not None:
        try:
            ida_funcs.reanalyze_function(owner)
        except Exception:
            pass
