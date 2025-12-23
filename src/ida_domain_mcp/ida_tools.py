
import sys
if sys.version_info < (3, 12):
    raise RuntimeError("Python 3.12 or higher is required for the MCP plugin")

from typing import Optional

from ida_domain import Database
from ida_domain.database import IdaCommandOptions

from ida_pro_mcp.ida_mcp.api_core import (
    idb_meta,
    lookup_funcs,
    cursor_addr,
    cursor_func,
    cursor_func,
    list_funcs,
    list_globals,
    imports,
    strings,
    segments,
    local_types
)

from ida_pro_mcp.ida_mcp.api_analysis import (
    decompile,
    disasm,
    xrefs_to,
    xrefs_to_field,
    callees,
    callers,
    entrypoints,
    analyze_funcs,
    find_bytes,
    find_insns,
    basic_blocks,
    find_paths,
    search,
    find_insn_operands,
    export_funcs,
    callgraph,
    xref_matrix,
    analyze_strings
)

from ida_pro_mcp.ida_mcp.api_debug import (
    dbg_start,
    dbg_exit,
    dbg_continue,
    dbg_run_to,
    dbg_step_into,
    dbg_step_over,
    dbg_list_bps,
    dbg_add_bp,
    dbg_delete_bp,
    dbg_enable_bp,
    dbg_regs,
    dbg_regs_thread,
    dbg_regs_cur,
    dbg_gpregs_thread,
    dbg_current_gpregs,
    dbg_regs_for_thread,
    dbg_current_regs,
    dbg_callstack,
    dbg_read_mem,
    dbg_write_mem
)

from ida_pro_mcp.ida_mcp.api_memory import (
    get_bytes,
    get_u8,
    get_u16,
    get_u32,
    get_u64,
    get_string,
    get_global_value,
    patch
)

from ida_pro_mcp.ida_mcp.api_modify import (
    set_comments,
    patch_asm,
    rename
)

from ida_pro_mcp.ida_mcp.api_python import (
    py_eval
)

from ida_pro_mcp.ida_mcp.api_stack import (
    stack_frame,
    declare_stack,
    delete_stack
)

from ida_pro_mcp.ida_mcp.api_types import (
    declare_type,
    structs,
    struct_info,
    read_struct,
    search_structs,
    apply_types,
    infer_types
)

def open_database(
    db_path: str,
    *,
    auto_analysis: bool = True,
    new_database: bool = False,
    save_on_close: bool = False,
) -> Database:
    """
    Open an IDA database and return the handle.

    - auto_analysis: whether to run auto-analysis when opening
    - new_database : whether to force creating a new .idb/.i64
    - save_on_close: default save behavior if db.close() is called without a save argument
    """
    ida_opts = IdaCommandOptions(
        auto_analysis=auto_analysis,
        new_database=new_database,
    )

    db = Database.open(
        path=db_path,
        args=ida_opts,
        save_on_close=save_on_close,
    )
    # If opening fails a DatabaseError is raised; caller may catch as needed.  [oai_citation:3‡ida-domain-llms-full.txt](sediment://file_000000005d2c722fb252b8f677a8064d)
    return db


def close_database(
    db: Optional[Database],
    *,
    save: Optional[bool] = None,
) -> None:
    """
    Close an open IDA database.

    - save=None : use the save_on_close strategy specified at open()
    - save=True : force saving analysis results
    - save=False : discard modifications
    """
    if db is None:
        return

    # Defensive: it may already have been closed
    if hasattr(db, "is_open") and not db.is_open():
        return

    # Database.close(save) follows documented save/discard logic  [oai_citation:4‡ida-domain-llms-full.txt](sediment://file_000000005d2c722fb252b8f677a8064d)
    db.close(save=save)
