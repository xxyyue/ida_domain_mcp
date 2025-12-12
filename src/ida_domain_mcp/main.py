import argparse
from urllib.parse import urlparse
import json
import traceback
import multiprocessing as mp
from mcp.server.fastmcp import FastMCP
from multiprocessing.connection import Connection
from typing import Dict, Tuple, Any



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
async def get_metadata(project_name: str) -> str:
    """
    Get basic metadata of the currently opened IDB (architecture, bitness,
    segment count, function stats, etc.).

    When to use:
    - You already opened the project via `open_database` and want a quick overview.
    - Before deciding next steps (decompile/search/iterate) to get a high-level picture.

    Do NOT use when:
    - No database is open for this `project_name` yet (open with `open_database` first).
    - You need detailed info about specific objects (functions/structures),
      use the dedicated tools instead.

    Parameters and constraints:
    - project_name: Logical project name. Must refer to an open and live worker.

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_metadata")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def open_database(
    project_name: str,
    db_path: str,
    auto_analysis: bool = True,
    new_database: bool = False,
    save_on_close: bool = False,
) -> str:
    """
    Open an IDA database (IDB/binary) for the given project in a dedicated
    worker process.

    When to use:
    - Initialize the database session for `project_name` before using tools requiring IDA state.
    - Isolate multiple projects or analyze them in parallel.

    Do NOT use when:
    - This `project_name` is already open and the worker is alive (returns {"status": "already_open"}).
    - You only need to read the current session; use other tools (e.g., `get_metadata`).

    Parameters and constraints:
    - project_name: Logical project id for multi-project separation; prefer a stable identifier.
    - db_path: Path to an IDA-openable database or binary (.i64/.idb or a raw binary IDA can parse).
    - auto_analysis: Whether to run IDA auto-analysis after opening (default True).
    - new_database: True when creating from a raw binary; usually False for existing .i64/.idb.
    - save_on_close: Default save behavior on close (can be overridden by `close_database(save=...)`).

    Returns: JSON string; on success {"status": "opened"}.
    On failure, raises an exception and cleans up the created process/pipe.
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
    return json.dumps({"status": "opened"}, ensure_ascii=False)


@mcp.tool()
async def get_function_by_name(project_name: str, name: str) -> str:
    """
    Get a function by its exact name including address, metadata and, if available,
    a short decompiled snippet.

    When to use:
    - You know the exact function name (e.g., 'NtCreateThreadEx', 'sub_140001000').
    - You want its address, metadata, or a short pseudocode snippet.

    Do NOT use when:
    - You only have an address -> use `get_function_by_address`.
    - You only have fuzzy keywords -> use listing/filtering tools (e.g., `list_functions_filter`).

    Parameters and constraints:
    - project_name: Opened project name.
    - name: Exact function name. Case-sensitivity depends on the database; prefer exact match.

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_function_by_name", name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_function_by_address(project_name: str, address: int | str) -> str:
    """
    Get a function by its start address, including metadata and, if available,
    a short decompiled snippet.

    When to use:
    - You know the function's start address (virtual address as int).
    - You want to confirm which function covers that address.

    Do NOT use when:
    - You only have a name -> use `get_function_by_name`.
    - The address is not inside any function (result may be empty/invalid).

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Integer address, preferably the function start. Internally sent as hex.

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_function_by_address", ensure_hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def convert_number(project_name: str, text: str, size: int) -> str:
    """
    Convert a numeric text (decimal or hexadecimal) into multiple representations
    (e.g., hex, endianness-aware views, sized values).

    When to use:
    - You need quick conversions for immediates/offsets during analysis.
    - You want to validate the value under different widths.

    Do NOT use when:
    - The input is not a valid numeric text.
    - You need massive batch conversions (script that on your side instead).

    Parameters and constraints:
    - project_name: Opened project name.
    - text: Numeric text, supports decimal or hex with 0x prefix.
    - size: Target byte width; typical values are 1/2/4/8. Wider than arch bitness may be meaningless.

    Returns: JSON string.
    """
    result = _call_project(project_name, "convert_number", text, size)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_functions_filter(
    project_name: str,
    offset: int,
    count: int,
    filter: str,
) -> str:
    """
    List functions matching `filter` with pagination.

    When to use:
    - You need name-based filtering by keyword/prefix/substring.
    - You want paginated results to avoid oversized responses.

    Do NOT use when:
    - You know the exact function name (prefer `get_function_by_name`).
    - You need address-based selection (use address-oriented tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - offset: Start index (>= 0).
    - count: Number of items to return (> 0). Very large values may slow down responses.
    - filter: Name pattern; typically substring/prefix (details depend on backend).

    Returns: JSON string.
    """
    result = _call_project(project_name, "list_functions_filter", offset, count, filter)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_functions(project_name: str, offset: int, count: int) -> str:
    """
    List all functions with pagination.

    When to use:
    - You want to iterate/browse the function list page by page.

    Do NOT use when:
    - You only need a specific function (use `get_function_by_name` or `get_function_by_address`).

    Parameters and constraints:
    - project_name: Opened project name.
    - offset: Start index (>= 0).
    - count: Number of items to return (> 0). Very large values may impact performance.

    Returns: JSON string.
    """
    result = _call_project(project_name, "list_functions", offset, count)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_globals_filter(
    project_name: str,
    offset: int,
    count: int,
    filter: str,
) -> str:
    """
    List globals matching `filter` with pagination.

    When to use:
    - You need name-based filtering of global variables/symbols.

    Do NOT use when:
    - You know the exact global name and only need that single item (consider direct reads/rename tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - offset: Start index (>= 0).
    - count: Number of items to return (> 0).
    - filter: Name matching string (typically substring).

    Returns: JSON string.
    """
    result = _call_project(project_name, "list_globals_filter", offset, count, filter)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_globals(project_name: str, offset: int, count: int) -> str:
    """
    List all globals with pagination.

    When to use:
    - You need to browse all globals page by page.

    Do NOT use when:
    - You only need a specific global variable (use dedicated tools to read/rename it).

    Parameters and constraints:
    - project_name: Opened project name.
    - offset: Start index (>= 0).
    - count: Number of items to return (> 0).

    Returns: JSON string.
    """
    result = _call_project(project_name, "list_globals", offset, count)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_imports(project_name: str, offset: int, count: int) -> str:
    """
    List imported symbols and their modules with pagination.

    When to use:
    - You want to quickly browse external API dependencies page by page.

    Do NOT use when:
    - You only need a single specific import (combine with filtering/searching instead).

    Parameters and constraints:
    - project_name: Opened project name.
    - offset: Start index (>= 0).
    - count: Number of items to return (> 0).

    Returns: JSON string.
    """
    result = _call_project(project_name, "list_imports", offset, count)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_strings_filter(
    project_name: str,
    offset: int,
    count: int,
    filter: str,
) -> str:
    """
    List strings matching `filter` with pagination.

    When to use:
    - You are searching for strings containing a keyword/pattern.

    Do NOT use when:
    - You need to read a string at a specific address (use `data_read_string`).

    Parameters and constraints:
    - project_name: Opened project name.
    - offset: Start index (>= 0).
    - count: Number of items to return (> 0).
    - filter: Matching keyword/pattern (exact behavior depends on backend implementation).

    Returns: JSON string.
    """
    result = _call_project(project_name, "list_strings_filter", offset, count, filter)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_strings(project_name: str, offset: int, count: int) -> str:
    """
    List all strings with pagination.

    When to use:
    - You want to browse or export all strings page by page.

    Do NOT use when:
    - You only need the string content at a specific address (use `data_read_string`).

    Parameters and constraints:
    - project_name: Opened project name.
    - offset: Start index (>= 0).
    - count: Number of items to return (> 0).

    Returns: JSON string.
    """
    result = _call_project(project_name, "list_strings", offset, count)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_segments(project_name: str) -> str:
    """
    List all segments in the binary (name, ranges, etc.).

    When to use:
    - You need to understand segment layout to guide address selection and reads.

    Do NOT use when:
    - You need more specific section/attribute details (use specialized tools).

    Parameters and constraints:
    - project_name: Opened project name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "list_segments")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_local_types(project_name: str) -> str:
    """
    List all Local Types in the database.

    When to use:
    - You want to review available typedef/struct/union type definitions.

    Do NOT use when:
    - You only care about a specific type (use `get_struct_info_simple` / `analyze_struct_detailed`).

    Parameters and constraints:
    - project_name: Opened project name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "list_local_types")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def decompile_function(project_name: str, address: int | str) -> str:
    """
    Decompile the function at the given address into pseudocode (if available).

    When to use:
    - You need a high-level semantic view (e.g., Hex-Rays output).

    Do NOT use when:
    - The address is not the function start (may fail or return nothing).
    - The function is huge/complex and performance is critical (decompilation is expensive).

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Function start address (int). Internally sent as hex.

    Returns: JSON string.
    """
    result = _call_project(project_name, "decompile_function", ensure_hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def disassemble_function(project_name: str, start_address: int | str) -> str:
    """
    Return the assembly for a function (compatible with older IDA API styles).

    When to use:
    - You need the instruction-level view rather than pseudocode.

    Do NOT use when:
    - You need cross-function/linear sweep listings (use specialized tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - start_address: Function start address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "disassemble_function", ensure_hex(start_address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_xrefs_to(project_name: str, address: int | str) -> str:
    """
    Get all cross references (xrefs to) the given address.

    When to use:
    - You want to know who references an address (function/global/string).

    Do NOT use when:
    - You want outgoing references (xrefs from) instead (not provided here).

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Target address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_xrefs_to", ensure_hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_xrefs_to_field(
    project_name: str,
    struct_name: str,
    field_name: str,
) -> str:
    """
    Get all cross references to a specific structure field (member).

    When to use:
    - You know the structure and field name and want to locate its usage sites.

    Do NOT use when:
    - The structure or field is not defined in Local Types.

    Parameters and constraints:
    - project_name: Opened project name.
    - struct_name: Structure name (as in Local Types).
    - field_name: Exact field/member name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_xrefs_to_field", struct_name, field_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_callees(project_name: str, function_address: int | str) -> str:
    """
    Get all direct callees of a function (outgoing edges).

    When to use:
    - You are building/browsing a call graph and need the callee list.

    Do NOT use when:
    - You need the callers of this function (use `get_callers`).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_callees", ensure_hex(function_address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_callers(project_name: str, function_address: int | str) -> str:
    """
    Get all direct callers of a function (incoming edges).

    When to use:
    - You want to analyze how/where this function is entered/used.

    Do NOT use when:
    - You need the callee list inside this function (use `get_callees`).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_callers", ensure_hex(function_address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_entry_points(project_name: str) -> str:
    """
    Get all entry points in the database.

    When to use:
    - You want to learn possible program start paths (e.g., `start`, `WinMain`).

    Do NOT use when:
    - You only need details of a specific entry function (use function queries).

    Parameters and constraints:
    - project_name: Opened project name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_entry_points")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_comment(project_name: str, address: int | str, comment: str) -> str:
    """
    Set a comment at the given address and sync it to disassembly/pseudocode when possible.

    When to use:
    - Annotate important locations, magic values, calling conventions, etc.

    Do NOT use when:
    - You intend to rename a symbol (use renaming tools instead).

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Target address (int).
    - comment: Comment text; excessive length may be truncated or render poorly.

    Returns: JSON string.
    """
    result = _call_project(project_name, "set_comment", ensure_hex(address), comment)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def rename_local_variable(
    project_name: str,
    function_address: int | str,
    old_name: str,
    new_name: str,
) -> str:
    """
    Rename a local variable within the specified function.

    When to use:
    - Improve readability by giving meaningful names to auto-generated/ambiguous locals.

    Do NOT use when:
    - You want to rename a global variable (use `rename_global_variable`).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).
    - old_name: Existing local variable name.
    - new_name: New name; must follow naming rules and avoid conflicts.

    Returns: JSON string.
    """
    result = _call_project(project_name, "rename_local_variable", ensure_hex(function_address), old_name, new_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def rename_global_variable(
    project_name: str,
    old_name: str,
    new_name: str,
) -> str:
    """
    Rename a global variable/symbol.

    When to use:
    - Assign clearer semantics to meaningless or auto-generated global names.

    Do NOT use when:
    - Renaming a function or a local variable (use `rename_function` / `rename_local_variable`).

    Parameters and constraints:
    - project_name: Opened project name.
    - old_name: Current global name (must exist).
    - new_name: Target name; avoid conflicts and follow naming rules.

    Returns: JSON string.
    """
    result = _call_project(project_name, "rename_global_variable", old_name, new_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_global_variable_type(
    project_name: str,
    variable_name: str,
    new_type: str,
) -> str:
    """
    Set the type of a global variable.

    When to use:
    - You have identified the semantics of a global and want to assign a C/Local Type.

    Do NOT use when:
    - Setting a function prototype or a local variable type (use the respective tool).

    Parameters and constraints:
    - project_name: Opened project name.
    - variable_name: Global variable name.
    - new_type: Type string (C syntax or an existing Local Type name).

    Returns: JSON string.
    """
    result = _call_project(project_name, "set_global_variable_type", variable_name, new_type)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def patch_address_assembles(
    project_name: str,
    address: int | str,
    instructions: str,
) -> str:
    """
    Patch code at a given address using assembly text (assemble then write).

    When to use:
    - Quickly modify instructions to validate a hypothesis or craft a PoC.

    Do NOT use when:
    - You need to modify data sections (this module mostly offers readers for data).
    - The architecture/assembly syntax mismatches the database (assembly will fail).

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Start address (int).
    - instructions: Assembly text, typically line-separated; must match current arch/syntax.

    Returns: JSON string.
    """
    result = _call_project(project_name, "patch_address_assembles", ensure_hex(address), instructions)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_global_variable_value_by_name(
    project_name: str,
    variable_name: str,
) -> str:
    """
    Read the static value of a global variable (if statically determinable).

    When to use:
    - The value can be computed statically (e.g., constant, initialized data).

    Do NOT use when:
    - The value only exists at runtime (cannot be determined statically).

    Parameters and constraints:
    - project_name: Opened project name.
    - variable_name: Global variable name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_global_variable_value_by_name", variable_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_global_variable_value_at_address(
    project_name: str,
    address: int | str,
) -> str:
    """
    Read the static value of a global variable by its address (if determinable).

    When to use:
    - You have the address of a global but not its name.

    Do NOT use when:
    - The value depends on runtime state (not statically determinable).

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Address of the global (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_global_variable_value_at_address", ensure_hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def rename_function(
    project_name: str,
    function_address: int | str,
    new_name: str,
) -> str:
    """
    Rename a function.

    When to use:
    - Replace auto-generated names like `sub_XXXXXXXX` with semantic names.

    Do NOT use when:
    - Renaming globals or locals (use respective tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).
    - new_name: New function name; avoid conflicts and follow naming rules.

    Returns: JSON string.
    """
    result = _call_project(project_name, "rename_function", ensure_hex(function_address), new_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_function_prototype(
    project_name: str,
    function_address: int | str,
    prototype: str,
) -> str:
    """
    Set the function prototype (return type, parameters, calling convention, etc.).

    When to use:
    - You have inferred the signature and want better pseudocode and type propagation.

    Do NOT use when:
    - You intend to set variable/structure types (use the respective type tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).
    - prototype: C-style prototype, must be accepted by IDA/decompiler.

    Returns: JSON string.
    """
    result = _call_project(project_name, "set_function_prototype", ensure_hex(function_address), prototype)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def declare_c_type(project_name: str, c_declaration: str) -> str:
    """
    Create or update Local Types from a C declaration.

    When to use:
    - Introduce/modify typedef/struct/union definitions for later application.

    Do NOT use when:
    - You only need to query existing types (use `list_local_types` or struct query tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - c_declaration: Full C declaration; syntax must be valid and referenced types resolvable.

    Returns: JSON string.
    """
    result = _call_project(project_name, "declare_c_type", c_declaration)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_local_variable_type(
    project_name: str,
    function_address: int | str,
    variable_name: str,
    new_type: str,
) -> str:
    """
    Set the type of a local variable in a function.

    When to use:
    - Assign the real type to improve decompiler accuracy.

    Do NOT use when:
    - Dealing with globals or function prototypes (use respective tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).
    - variable_name: Local variable name.
    - new_type: C-style type or Local Type name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "set_local_variable_type", ensure_hex(function_address), variable_name, new_type)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_stack_frame_variables(
    project_name: str,
    function_address: int | str,
) -> str:
    """
    Retrieve the stack frame variables for a given function (names, offsets, types, etc.).

    When to use:
    - You want to understand the layout and known types of locals.

    Do NOT use when:
    - You intend to modify/create/delete stack variables (use respective tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_stack_frame_variables", ensure_hex(function_address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_defined_structures(project_name: str) -> str:
    """
    Return a list of all defined structure names.

    When to use:
    - Quickly enumerate available structures for further queries/searches.

    Do NOT use when:
    - You need structure field details (use `analyze_struct_detailed`).

    Parameters and constraints:
    - project_name: Opened project name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_defined_structures")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def analyze_struct_detailed(project_name: str, name: str) -> str:
    """
    Detailed analysis of a structure including all fields, offsets, and types.

    When to use:
    - You need the complete layout and field details of a structure.

    Do NOT use when:
    - You only need existence or brief info (use `get_struct_info_simple`).

    Parameters and constraints:
    - project_name: Opened project name.
    - name: Structure name (must exist).

    Returns: JSON string.
    """
    result = _call_project(project_name, "analyze_struct_detailed", name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_struct_at_address(
    project_name: str,
    address: int | str,
    struct_name: str,
) -> str:
    """
    Interpret memory at an address as the given structure and return field values.

    When to use:
    - An instance of the structure is located at the address and you want field values quickly.

    Do NOT use when:
    - The structure is undefined or the address is not readable.

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Start address (int).
    - struct_name: Structure name defined in Local Types.

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_struct_at_address", ensure_hex(address), struct_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_struct_info_simple(project_name: str, name: str) -> str:
    """
    Return basic information about a structure (lighter than the detailed version).

    When to use:
    - You only need to confirm existence or basic attributes.

    Do NOT use when:
    - You need full field layout (use `analyze_struct_detailed`).

    Parameters and constraints:
    - project_name: Opened project name.
    - name: Structure name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "get_struct_info_simple", name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def search_structures(project_name: str, filter: str) -> str:
    """
    Search for structures by name pattern.

    When to use:
    - You only remember part of the name/prefix and need fuzzy matching.

    Do NOT use when:
    - You know the exact name and need details (use `analyze_struct_detailed`).

    Parameters and constraints:
    - project_name: Opened project name.
    - filter: Name matching string (typically substring/prefix).

    Returns: JSON string.
    """
    result = _call_project(project_name, "search_structures", filter)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def rename_stack_frame_variable(
    project_name: str,
    function_address: int | str,
    old_name: str,
    new_name: str,
) -> str:
    """
    Rename a stack frame variable within a function.

    When to use:
    - Improve readability by giving a more accurate name to a stack variable.

    Do NOT use when:
    - Renaming a global or a function (use respective rename tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).
    - old_name: Original variable name.
    - new_name: New variable name; avoid conflicts with existing variables.

    Returns: JSON string.
    """
    result = _call_project(project_name, "rename_stack_frame_variable", ensure_hex(function_address), old_name, new_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def create_stack_frame_variable(
    project_name: str,
    function_address: int | str,
    offset: int | str,
    variable_name: str,
    type_name: str,
) -> str:
    """
    Create a stack frame variable in a function with a specific offset, name, and type.

    When to use:
    - You identified a stack offset with semantics and want to model it as a variable.

    Do NOT use when:
    - The variable already exists or the offset conflicts/overlaps with an existing variable.

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).
    - offset: Byte offset in the stack frame (int). Internally sent as hex string.
    - variable_name: Variable name.
    - type_name: C-style type or an existing Local Type name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "create_stack_frame_variable", ensure_hex(function_address), ensure_hex(offset), variable_name, type_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_stack_frame_variable_type(
    project_name: str,
    function_address: int | str,
    variable_name: str,
    type_name: str,
) -> str:
    """
    Set the type of a stack frame variable of a function.

    When to use:
    - Assign the real type to a stack variable to improve decompilation quality.

    Do NOT use when:
    - The target is a non-stack local or a global (use respective tools).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).
    - variable_name: Stack variable name.
    - type_name: C-style type or Local Type name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "set_stack_frame_variable_type", ensure_hex(function_address), variable_name, type_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def delete_stack_frame_variable(
    project_name: str,
    function_address: int | str,
    variable_name: str,
) -> str:
    """
    Delete a specific stack frame variable from a function.

    When to use:
    - Clean up incorrectly identified or no longer needed stack variables.

    Do NOT use when:
    - The variable name does not exist (no effect or failure).

    Parameters and constraints:
    - project_name: Opened project name.
    - function_address: Function start address (int).
    - variable_name: Stack variable name.

    Returns: JSON string.
    """
    result = _call_project(project_name, "delete_stack_frame_variable", ensure_hex(function_address), variable_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def read_memory_bytes(
    project_name: str,
    memory_address: int | str,
    size: int | str,
) -> str:
    """
    Read raw bytes at a given address with a specified size.

    When to use:
    - Inspect raw data in code/data segments at arbitrary addresses.

    Do NOT use when:
    - The address is outside any mapped/readable segment.
    - You plan to read very large ranges (prefer paged/chunked reads).

    Parameters and constraints:
    - project_name: Opened project name.
    - memory_address: Start address (int).
    - size: Number of bytes to read (> 0).

    Returns: JSON string (often includes hex/raw representations).
    """
    result = _call_project(project_name, "read_memory_bytes", ensure_hex(memory_address), ensure_int(size))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_byte(project_name: str, address: int | str) -> str:
    """
    Read the 1-byte value at the specified address.

    When to use:
    - You only need a single-byte value for a quick check.

    Do NOT use when:
    - You need multi-byte values or strings (use other readers).

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Target address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "data_read_byte", ensure_hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_word(project_name: str, address: int | str) -> str:
    """
    Read the 2-byte value (WORD) at the specified address.

    When to use:
    - You need a 2-byte width value.

    Do NOT use when:
    - Architecture/alignment constraints make unaligned reads ambiguous.

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Target address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "data_read_word", ensure_hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_dword(project_name: str, address: int | str) -> str:
    """
    Read the 4-byte value (DWORD) at the specified address.

    When to use:
    - You need a 4-byte width value.

    Do NOT use when:
    - The address is out of range or unreadable.

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Target address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "data_read_dword", ensure_hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_qword(project_name: str, address: int | str) -> str:
    """
    Read the 8-byte value (QWORD) at the specified address.

    When to use:
    - You need an 8-byte width value (commonly 64-bit pointers/values).

    Do NOT use when:
    - Unaligned addresses make the value meaningless in your context.

    Parameters and constraints:
    - project_name: Opened project name.
    - address: Target address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "data_read_qword", ensure_hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_string(project_name: str, address: int | str) -> str:
    """
    Read the string at the specified address (encoding/termination as recognized by the DB).

    When to use:
    - You want the content and basic metadata of a constant string.

    Do NOT use when:
    - The string is not correctly recognized by IDA or encoding is unknown (results may be incomplete).

    Parameters and constraints:
    - project_name: Opened project name.
    - address: String start address (int).

    Returns: JSON string.
    """
    result = _call_project(project_name, "data_read_string", ensure_hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def close_database(project_name: str, save: bool | None = None) -> str:
    """
    Close the project's IDA database and terminate its worker process.

    When to use:
    - You finished analysis or need to free resources/switch databases.

    Do NOT use when:
    - The project is not open or the worker already exited (returns {"status": "already_closed"}).

    Parameters and constraints:
    - project_name: Logical project name.
    - save: Whether to save changes. True/False to force; None to use `open_database`'s `save_on_close`.

    Returns: JSON string; on success {"status": "closed"}. Raises on failure.
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
    return json.dumps({"status": "closed"}, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description="ida_domain MCP Server")
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)")
    args = parser.parse_args()
    
    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            mcp.settings.host = url.hostname
            mcp.settings.port = url.port
            # NOTE: npx @modelcontextprotocol/inspector for debugging
            print(f"MCP Server availabile at http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.settings.log_level = "INFO"
            mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass
    
if __name__ == "__main__":
    main()
