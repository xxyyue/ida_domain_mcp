import argparse
from urllib.parse import urlparse
import json
import traceback
import multiprocessing as mp
import fastmcp
from fastmcp import FastMCP
from multiprocessing.connection import Connection
from typing import Dict, Tuple, Any, Annotated
import os
import logging

# Import parameter/TypedDict definitions to align with ida_pro_mcp API
from ida_domain_mcp.types import (
    ListQuery,
    NumberConversion,
    MemoryRead,
    MemoryPatch,
    CommentOp,
    AsmPatchOp,
    RenameBatch,
    TypeApplication,
    StructRead,
    StackVarDecl,
    StackVarDelete,
    PathQuery,
    StructFieldQuery,
    StringFilter,
    InsnPattern,
    BreakpointOp,
)

logger = logging.getLogger(__name__)

# project_name -> (Process, parent_conn)
PROJECTS: Dict[str, Tuple[mp.Process, Connection]] = {}

def ensure_hex(address: int | str) -> str:
    if isinstance(address, int):
        address = hex(address)
    return address

def ensure_int(address: int | str) -> str:
    if isinstance(address, str):
        if address.startswith("0x"):
            return int(address, 16)
        address = int(address)
    return address

def _worker(conn: Connection):
    """Child process loop hosting an IDA Database via ida_tools."""
    db = None
    try:
        from ida_domain_mcp import ida_tools as tools
    except Exception as e:
        # If ida_tools cannot be imported in child, notify parent and exit
        err = {"ok": False, "error": f"failed to import ida_tools: {e}", "traceback": traceback.format_exc()}
        try:
            conn.send(err)
        except Exception:
            pass
        conn.close()
        return

    while True:
        try:
            msg = conn.recv()
        except EOFError:
            break
        except Exception as e:
            try:
                conn.send({"ok": False, "error": str(e), "traceback": traceback.format_exc()})
            except Exception:
                pass
            break

        if not isinstance(msg, dict):
            try:
                conn.send({"ok": False, "error": "invalid message"})
            except Exception:
                pass
            continue

        mtype = msg.get("type")
        try:
            if mtype == "open":
                db_path = msg["db_path"]
                auto_analysis = msg.get("auto_analysis", True)
                new_database = msg.get("new_database", False)
                save_on_close = msg.get("save_on_close", False)
                db = tools.open_database(
                    db_path,
                    auto_analysis=auto_analysis,
                    new_database=new_database,
                    save_on_close=save_on_close,
                )
                conn.send({"ok": True})
            elif mtype == "call":
                func_name = msg.get("func")
                args = msg.get("args", [])
                kwargs = msg.get("kwargs", {})
                if not func_name or not hasattr(tools, func_name):
                    conn.send({"ok": False, "error": f"unknown function: {func_name}"})
                    continue
                func = getattr(tools, func_name)
                result = func(*args, **kwargs)
                conn.send({"ok": True, "result": result})
            elif mtype == "close":
                save = msg.get("save", None)
                try:
                    tools.close_database(db, save=save)
                finally:
                    db = None
                conn.send({"ok": True})
                break
            else:
                conn.send({"ok": False, "error": f"unknown message type: {mtype}"})
        except Exception as e:
            conn.send({"ok": False, "error": str(e), "traceback": traceback.format_exc()})

    try:
        conn.close()
    except Exception:
        pass

mcp = FastMCP("IDA Domain MCP Server")


def _ensure_project(project_name: str) -> Tuple[mp.Process, Connection]:
    if project_name not in PROJECTS:
        raise ValueError(f"Project '{project_name}' is not open")
    return PROJECTS[project_name]


def _call_project(project_name: str, func: str, *args: Any, **kwargs: Any) -> Any:
    proc, conn = _ensure_project(project_name)
    if not proc.is_alive():
        # cleanup stale mapping
        try:
            conn.close()
        except Exception:
            pass
        del PROJECTS[project_name]
        raise RuntimeError(f"Project '{project_name}' worker not running")

    conn.send({"type": "call", "func": func, "args": list(args), "kwargs": kwargs})
    reply = conn.recv()
    if not isinstance(reply, dict) or not reply.get("ok"):
        raise RuntimeError(f"call {func} failed: {reply.get('error') if isinstance(reply, dict) else reply}")
    return reply.get("result")

@mcp.tool()
async def open_database(
    project_name: Annotated[str, "Project name for worker routing"],
    db_path: Annotated[str, "Path to IDA database (.i64/.idb) or binary"],
    auto_analysis: Annotated[bool, "Run IDA auto analysis after open"] = True,
    new_database: Annotated[bool, "Create new database from raw binary"] = False,
    save_on_close: Annotated[bool, "Default save behavior on close"] = False,
):
    """
    Open an IDA database (IDB/binary) for the given project in a dedicated worker process.
    """
    if project_name in PROJECTS:
        proc, _ = PROJECTS[project_name]
        if proc.is_alive():
            return json.dumps({"status": "already_open"}, ensure_ascii=False)
        # stale; clean up mapping
        try:
            PROJECTS.pop(project_name, None)
        except Exception:
            pass

    parent_conn, child_conn = mp.Pipe()
    proc = mp.Process(target=_worker, args=(child_conn,), daemon=True)
    proc.start()

    # The child sends an error immediately if ida_tools import failed; otherwise wait for open ack
    # Send open request
    parent_conn.send(
        {
            "type": "open",
            "db_path": db_path,
            "auto_analysis": auto_analysis,
            "new_database": new_database,
            "save_on_close": save_on_close,
        }
    )
    reply = parent_conn.recv()
    if not isinstance(reply, dict) or not reply.get("ok"):
        # ensure process is terminated
        try:
            parent_conn.close()
        except Exception:
            pass
        try:
            if proc.is_alive():
                proc.terminate()
        except Exception:
            pass
        err = reply.get("error") if isinstance(reply, dict) else str(reply)
        raise RuntimeError(f"open_database failed: {err}")

    PROJECTS[project_name] = (proc, parent_conn)
    return {"status": "opened"}


@mcp.tool()
async def idb_meta(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Get IDB metadata
    """
    return _call_project(project_name, "idb_meta")


@mcp.tool()
async def lookup_funcs(
    project_name: Annotated[str, "Project name for worker routing"],
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
):
    """
    Get functions by address or name (auto-detects)
    """
    return _call_project(project_name, "lookup_funcs", queries)


@mcp.tool()
async def cursor_addr(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Get current address
    """
    return _call_project(project_name, "cursor_addr")


@mcp.tool()
async def int_convert(
    project_name: Annotated[str, "Project name for worker routing"],
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
):
    """
    Convert numbers to different formats
    """
    return _call_project(project_name, "int_convert", inputs)


@mcp.tool()
async def list_funcs(
    project_name: Annotated[str, "Project name for worker routing"],
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination",
    ],
):
    """
    List functions
    """
    return _call_project(project_name, "list_funcs", queries)


@mcp.tool()
async def list_globals(
    project_name: Annotated[str, "Project name for worker routing"],
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
):
    """
    List globals
    """
    return _call_project(project_name, "list_globals", queries)


@mcp.tool()
async def imports(
    project_name: Annotated[str, "Project name for worker routing"],
    offset: Annotated[int, "Offset"],
    count: Annotated[int, "Count (0=all)"],
):
    """
    List imports
    """
    return _call_project(project_name, "imports", offset, count)


@mcp.tool()
async def strings(
    project_name: Annotated[str, "Project name for worker routing"],
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List strings with optional filtering and pagination",
    ],
):
    """
    List strings
    """
    return _call_project(project_name, "strings", queries)


@mcp.tool()
async def segments(project_name: Annotated[str, "Project name for worker routing"]):
    """
    List all segments
    """
    return _call_project(project_name, "segments")


@mcp.tool()
async def local_types(project_name: Annotated[str, "Project name for worker routing"]):
    """
    List local types
    """
    return _call_project(project_name, "local_types")


@mcp.tool()
async def decompile(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Function addresses to decompile"],
):
    """
    Decompile functions to pseudocode
    """
    return _call_project(project_name, "decompile", addrs)


@mcp.tool()
async def disasm(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Function addresses to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
):
    """
    Disassemble functions to assembly instructions
    """
    return _call_project(project_name, "disasm", addrs, max_instructions, offset)


@mcp.tool()
async def xrefs_to(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Addresses to find cross-references to"],
):
    """
    Get all cross-references to specified addresses
    """
    return _call_project(project_name, "xrefs_to", addrs)


@mcp.tool()
async def xrefs_to_field(
    project_name: Annotated[str, "Project name for worker routing"],
    queries: list[StructFieldQuery] | StructFieldQuery,
):
    """
    Get cross-references to structure fields
    """
    return _call_project(project_name, "xrefs_to_field", queries)


@mcp.tool()
async def callees(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Function addresses to get callees for"],
):
    """
    Get all functions called by the specified functions
    """
    return _call_project(project_name, "callees", addrs)


@mcp.tool()
async def callers(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Function addresses to get callers for"],
):
    """
    Get all functions that call the specified functions
    """
    return _call_project(project_name, "callers", addrs)


@mcp.tool()
async def entrypoints(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Get entry points
    """
    return _call_project(project_name, "entrypoints")


@mcp.tool()
async def set_comments(
    project_name: Annotated[str, "Project name for worker routing"],
    items: list[CommentOp] | CommentOp,
):
    """
    Set comments at addresses (both disassembly and decompiler views)
    """
    return _call_project(project_name, "set_comments", items)


@mcp.tool()
async def rename(
    project_name: Annotated[str, "Project name for worker routing"],
    batch: RenameBatch,
):
    """
    Unified rename operation for functions, globals, locals, and stack variables
    """
    return _call_project(project_name, "rename", batch)


@mcp.tool()
async def apply_types(
    project_name: Annotated[str, "Project name for worker routing"],
    applications: list[TypeApplication] | TypeApplication,
):
    """
    Apply types (function/global/local/stack)
    """
    return _call_project(project_name, "apply_types", applications)


@mcp.tool()
async def patch_asm(
    project_name: Annotated[str, "Project name for worker routing"],
    items: list[AsmPatchOp] | AsmPatchOp,
):
    """
    Patch assembly instructions at addresses
    """
    return _call_project(project_name, "patch_asm", items)


@mcp.tool()
async def get_global_value(
    project_name: Annotated[str, "Project name for worker routing"],
    queries: Annotated[
        list[str] | str, "Global variable addresses or names to read values from"
    ],
):
    """
    Read global variable values by address or name
    (auto-detects hex addresses vs names)
    """
    return _call_project(project_name, "get_global_value", queries)


@mcp.tool()
async def stack_frame(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Address(es)"],
):
    """
    Get stack vars
    """
    return _call_project(project_name, "stack_frame", addrs)


@mcp.tool()
async def structs(project_name: Annotated[str, "Project name for worker routing"]):
    """
    List all structures
    """
    return _call_project(project_name, "structs")


@mcp.tool()
async def struct_info(
    project_name: Annotated[str, "Project name for worker routing"],
    names: Annotated[list[str] | str, "Structure names to query"],
):
    """
    Get struct info
    """
    return _call_project(project_name, "struct_info", names)


@mcp.tool()
async def read_struct(
    project_name: Annotated[str, "Project name for worker routing"],
    queries: list[StructRead] | StructRead,
):
    """
    Read struct fields
    """
    return _call_project(project_name, "read_struct", queries)


@mcp.tool()
async def search_structs(
    project_name: Annotated[str, "Project name for worker routing"],
    filter: Annotated[
        str, "Case-insensitive substring to search for in structure names"
    ],
):
    """
    Search structs
    """
    return _call_project(project_name, "search_structs", filter)


@mcp.tool()
async def declare_stack(
    project_name: Annotated[str, "Project name for worker routing"],
    items: list[StackVarDecl] | StackVarDecl,
):
    """
    Create stack vars
    """
    return _call_project(project_name, "declare_stack", items)


@mcp.tool()
async def delete_stack(
    project_name: Annotated[str, "Project name for worker routing"],
    items: list[StackVarDelete] | StackVarDelete,
):
    """
    Delete stack vars
    """
    return _call_project(project_name, "delete_stack", items)


@mcp.tool()
async def declare_type(
    project_name: Annotated[str, "Project name for worker routing"],
    decls: Annotated[list[str] | str, "C type declarations"],
):
    """
    Declare types
    """
    return _call_project(project_name, "declare_type", decls)


@mcp.tool()
async def get_bytes(
    project_name: Annotated[str, "Project name for worker routing"],
    regions: list[MemoryRead] | MemoryRead,
):
    """
    Read bytes from memory addresses
    """
    return _call_project(project_name, "get_bytes", regions)


@mcp.tool()
async def get_u8(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[
        list[str] | str, "Addresses to read 8-bit unsigned integers from"
    ],
):
    """
    Read 8-bit unsigned integers from memory addresses
    """
    return _call_project(project_name, "get_u8", addrs)


@mcp.tool()
async def get_u16(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[
        list[str] | str, "Addresses to read 16-bit unsigned integers from"
    ],
):
    """
    Read 16-bit unsigned integers from memory addresses
    """
    return _call_project(project_name, "get_u16", addrs)


@mcp.tool()
async def get_u32(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[
        list[str] | str, "Addresses to read 32-bit unsigned integers from"
    ],
):
    """
    Read 32-bit unsigned integers from memory addresses
    """
    return _call_project(project_name, "get_u32", addrs)


@mcp.tool()
async def get_u64(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[
        list[str] | str, "Addresses to read 64-bit unsigned integers from"
    ],
):
    """
    Read 64-bit unsigned integers from memory addresses
    """
    return _call_project(project_name, "get_u64", addrs)


@mcp.tool()
async def get_string(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Addresses to read strings from"],
):
    """
    Read strings from memory addresses
    """
    return _call_project(project_name, "get_string", addrs)


@mcp.tool()
async def cursor_func(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Get current function
    """
    return _call_project(project_name, "cursor_func")


# Analysis: comprehensive, patterns, CFG, search, export, graphs

@mcp.tool()
async def analyze_funcs(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Function addresses to comprehensively analyze"],
):
    """
    Comprehensive function analysis: decompilation, xrefs, callees, strings, constants, blocks
    """
    return _call_project(project_name, "analyze_funcs", addrs)


@mcp.tool()
async def find_bytes(
    project_name: Annotated[str, "Project name for worker routing"],
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g. '48 8B ?? ??')"
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
):
    """
    Search for byte patterns in the binary (supports wildcards with ??)
    """
    return _call_project(project_name, "find_bytes", patterns, limit, offset)


@mcp.tool()
async def find_insns(
    project_name: Annotated[str, "Project name for worker routing"],
    sequences: Annotated[
        list[list[str]] | list[str], "Instruction mnemonic sequences to search for"
    ],
    limit: Annotated[int, "Max matches per sequence (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
):
    """
    Search for sequences of instruction mnemonics in the binary
    """
    return _call_project(project_name, "find_insns", sequences, limit, offset)


@mcp.tool()
async def basic_blocks(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Function addresses to get basic blocks for"],
    max_blocks: Annotated[int, "Max basic blocks per function (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N blocks (default: 0)"] = 0,
):
    """
    Get control flow graph basic blocks for functions
    """
    return _call_project(project_name, "basic_blocks", addrs, max_blocks, offset)


@mcp.tool()
async def find_paths(
    project_name: Annotated[str, "Project name for worker routing"],
    queries: list[PathQuery] | PathQuery,
):
    """
    Find execution paths between source and target addresses
    """
    return _call_project(project_name, "find_paths", queries)


@mcp.tool()
async def search(
    project_name: Annotated[str, "Project name for worker routing"],
    type: Annotated[
        str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"
    ],
    targets: Annotated[
        list[str | int] | str | int,
        "Search targets (strings, integers, or addresses)",
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
):
    """
    Search for patterns in the binary (strings, immediate values, or references)
    """
    return _call_project(project_name, "search", type, targets, limit, offset)


@mcp.tool()
async def find_insn_operands(
    project_name: Annotated[str, "Project name for worker routing"],
    patterns: list[InsnPattern] | InsnPattern,
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
):
    """
    Find instructions with specific mnemonics and operand values
    """
    return _call_project(project_name, "find_insn_operands", patterns, limit, offset)


@mcp.tool()
async def export_funcs(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Function addresses to export"],
    format: Annotated[str, "Export format: json (default), c_header, or prototypes"] = "json",
):
    """
    Export function data in various formats
    """
    return _call_project(project_name, "export_funcs", addrs, format)


@mcp.tool()
async def callgraph(
    project_name: Annotated[str, "Project name for worker routing"],
    roots: Annotated[
        list[str] | str, "Root function addresses to start call graph traversal from"
    ],
    max_depth: Annotated[int, "Maximum depth for call graph traversal"] = 5,
):
    """
    Build call graph starting from root functions
    """
    return _call_project(project_name, "callgraph", roots, max_depth)


@mcp.tool()
async def xref_matrix(
    project_name: Annotated[str, "Project name for worker routing"],
    entities: Annotated[list[str] | str, "Addresses to build cross-reference matrix for"],
):
    """
    Build matrix showing cross-references between entities
    """
    return _call_project(project_name, "xref_matrix", entities)


@mcp.tool()
async def analyze_strings(
    project_name: Annotated[str, "Project name for worker routing"],
    filters: list[StringFilter] | StringFilter,
    limit: Annotated[int, "Max matches per filter (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
):
    """
    Analyze and filter strings in the binary
    """
    return _call_project(project_name, "analyze_strings", filters, limit, offset)


# Debugger operations

@mcp.tool()
async def dbg_start(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Start debugger
    """
    return _call_project(project_name, "dbg_start")


@mcp.tool()
async def dbg_exit(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Exit debugger
    """
    return _call_project(project_name, "dbg_exit")


@mcp.tool()
async def dbg_continue(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Continue debugger
    """
    return _call_project(project_name, "dbg_continue")


@mcp.tool()
async def dbg_run_to(
    project_name: Annotated[str, "Project name for worker routing"],
    addr: Annotated[str, "Address"],
):
    """
    Run to address
    """
    return _call_project(project_name, "dbg_run_to", addr)


@mcp.tool()
async def dbg_step_into(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Step into
    """
    return _call_project(project_name, "dbg_step_into")


@mcp.tool()
async def dbg_step_over(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Step over
    """
    return _call_project(project_name, "dbg_step_over")


@mcp.tool()
async def dbg_list_bps(project_name: Annotated[str, "Project name for worker routing"]):
    """
    List breakpoints
    """
    return _call_project(project_name, "dbg_list_bps")


@mcp.tool()
async def dbg_add_bp(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Address(es) to add breakpoints at"],
):
    """
    Add breakpoints
    """
    return _call_project(project_name, "dbg_add_bp", addrs)


@mcp.tool()
async def dbg_delete_bp(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Address(es) to delete breakpoints from"],
):
    """
    Delete breakpoints
    """
    return _call_project(project_name, "dbg_delete_bp", addrs)


@mcp.tool()
async def dbg_enable_bp(
    project_name: Annotated[str, "Project name for worker routing"],
    items: list[BreakpointOp] | BreakpointOp,
):
    """
    Enable/disable breakpoints
    """
    return _call_project(project_name, "dbg_enable_bp", items)


@mcp.tool()
async def dbg_regs(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Get all registers
    """
    return _call_project(project_name, "dbg_regs")


@mcp.tool()
async def dbg_regs_thread(
    project_name: Annotated[str, "Project name for worker routing"],
    tids: Annotated[list[int] | int, "Thread ID(s) to get registers for"],
):
    """
    Get thread registers
    """
    return _call_project(project_name, "dbg_regs_thread", tids)


@mcp.tool()
async def dbg_regs_cur(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Get current thread registers
    """
    return _call_project(project_name, "dbg_regs_cur")


@mcp.tool()
async def dbg_gpregs_thread(
    project_name: Annotated[str, "Project name for worker routing"],
    tids: Annotated[list[int] | int, "Thread ID(s) to get GP registers for"],
):
    """
    Get GP registers for threads
    """
    return _call_project(project_name, "dbg_gpregs_thread", tids)


@mcp.tool()
async def dbg_current_gpregs(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Get current thread GP registers
    """
    return _call_project(project_name, "dbg_current_gpregs")


@mcp.tool()
async def dbg_regs_for_thread(
    project_name: Annotated[str, "Project name for worker routing"],
    thread_id: Annotated[int, "Thread ID"],
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
):
    """
    Get specific thread registers
    """
    return _call_project(project_name, "dbg_regs_for_thread", thread_id, register_names)


@mcp.tool()
async def dbg_current_regs(
    project_name: Annotated[str, "Project name for worker routing"],
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
):
    """
    Get specific current thread registers
    """
    return _call_project(project_name, "dbg_current_regs", register_names)


@mcp.tool()
async def dbg_callstack(project_name: Annotated[str, "Project name for worker routing"]):
    """
    Get call stack
    """
    return _call_project(project_name, "dbg_callstack")


@mcp.tool()
async def dbg_read_mem(
    project_name: Annotated[str, "Project name for worker routing"],
    regions: list[MemoryRead] | MemoryRead,
):
    """
    Read debug memory
    """
    return _call_project(project_name, "dbg_read_mem", regions)


@mcp.tool()
async def dbg_write_mem(
    project_name: Annotated[str, "Project name for worker routing"],
    regions: list[MemoryPatch] | MemoryPatch,
):
    """
    Write debug memory
    """
    return _call_project(project_name, "dbg_write_mem", regions)


# Memory patching

@mcp.tool()
async def patch(
    project_name: Annotated[str, "Project name for worker routing"],
    patches: list[MemoryPatch] | MemoryPatch,
):
    """
    Patch bytes at memory addresses with hex data
    """
    return _call_project(project_name, "patch", patches)


# Python evaluation

@mcp.tool()
async def py_eval(
    project_name: Annotated[str, "Project name for worker routing"],
    code: Annotated[str, "Python code"],
):
    """
    Execute Python code in IDA context
    """
    return _call_project(project_name, "py_eval", code)


# Type inference

@mcp.tool()
async def infer_types(
    project_name: Annotated[str, "Project name for worker routing"],
    addrs: Annotated[list[str] | str, "Addresses to infer types for"],
):
    """
    Infer types
    """
    return _call_project(project_name, "infer_types", addrs)


@mcp.tool()
async def close_database(
    project_name: Annotated[str, "Project name for worker routing"],
    save: Annotated[bool | None, "Override save_on_close for this close"] | None = None,
):
    """
    Close the project's IDA database and terminate its worker process.
    """
    proc, conn = _ensure_project(project_name)
    if not proc.is_alive():
        try:
            conn.close()
        except Exception:
            pass
        PROJECTS.pop(project_name, None)
        return json.dumps({"status": "already_closed"}, ensure_ascii=False)

    try:
        conn.send({"type": "close", "save": save})
        reply = conn.recv()
    except Exception as e:
        reply = {"ok": False, "error": str(e)}

    try:
        if proc.is_alive():
            proc.join(timeout=2.0)
    except Exception:
        pass
    if proc.is_alive():
        try:
            proc.terminate()
        except Exception:
            pass

    try:
        conn.close()
    except Exception:
        pass
    PROJECTS.pop(project_name, None)

    if not isinstance(reply, dict) or not reply.get("ok"):
        err = reply.get("error") if isinstance(reply, dict) else str(reply)
        raise RuntimeError(f"close_database failed: {err}")
    return {"status": "closed"}


def main():
    parser = argparse.ArgumentParser(description="ida_domain MCP Server")
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)")
    parser.add_argument("--streamable-http", action='store_true', help="Use Streamable HTTP instead of SSE (default)")
    args = parser.parse_args()
    IDADIR = os.getenv("IDADIR")
    if IDADIR is None:
        logger.warning("Warning: IDADIR environment variable is not set.")

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx @modelcontextprotocol/inspector for debugging
            fastmcp.settings.log_level = "INFO"
            if args.streamable_http:
                mcp.run(transport="http", host=url.hostname, port=url.port)
            else:
                mcp.run(transport="sse", host=url.hostname, port=url.port)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
