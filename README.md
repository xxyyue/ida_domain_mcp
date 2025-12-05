# ida-domain-mcp

A headless Model Context Protocol (MCP) server for IDA Pro built on top of `ida-domain`. It lets AI agents (or any MCP client) open and analyze IDA databases on demand — without launching the IDA manully — and control common reverse engineering workflows programmatically.

Unlike GUI-centric approaches, ida-domain-mcp spins up per-project worker processes on demand and loads binaries via an MCP tool call during the agent’s workflow. You don’t have to pre-load binaries at MCP server startup, and once configured, the whole flow can run fully automatically without human interaction.

## Example

```bash
# Start the MCP server (SSE mode)
uv run ida-domain-mcp --transport http://127.0.0.1:8744

# In another shell, run the test agent
uv run tests/agent.py
```
![demo](assets/demo.png)

## Why It’s Different
- Headless by design: No dependency on the IDA graphical UI. Uses `idat`/`idat64` (IDA’s headless runners) underneath via `ida-domain`.
- On-demand database loading: Call the `open_database` MCP tool at any time during the agent session to load a binary or IDB; no manual preloading required.
- Multi-project isolation: Each `project_name` runs in its own worker process; multiple binaries can be analyzed concurrently without interfering with each other.
- Agent-friendly: Returns JSON-serializable results (as strings) so LLM agents can easily parse and chain operations.

## Features (tools)
High-level categories of tools exposed via MCP (see `src/ida_domain_mcp/main.py` and `ida_tools.py` for the full list):
- Project/session management: `open_database`, `close_database`, `get_metadata`
- Navigation and listings: `list_segments`, `list_functions`, `list_functions_filter`, `list_globals`, `list_globals_filter`, `list_imports`, `list_strings`, `list_strings_filter`, `get_entry_points`
- Function-oriented: `get_function_by_name`, `get_function_by_address`, `get_callers`, `get_callees`, `decompile_function` (requires Hex-Rays), `disassemble_function`
- Cross-references: `get_xrefs_to`, `get_xrefs_to_field`
- Types and structures: `list_local_types`, `declare_c_type`, `get_defined_structures`, `analyze_struct_detailed`, `get_struct_info_simple`, `search_structures`, `get_stack_frame_variables`, `set_function_prototype`, `set_local_variable_type`, `set_global_variable_type`
- Renaming and comments: `rename_function`, `rename_local_variable`, `rename_stack_frame_variable`, `rename_global_variable`, `set_comment`
- Data access and patching: `read_memory_bytes`, `data_read_{byte,word,dword,qword,string}`, `get_global_variable_value_{by_name,at_address}`, `patch_address_assembles`

Notes:
- `decompile_function` requires a valid Hex-Rays license; otherwise use `disassemble_function`.
- Address parameters are accepted as integers by MCP entry points and are converted internally; results commonly encode addresses as hex strings.

## Requirements
- Python: 3.11+
- IDA: IDA Pro 9.1.0 or later installed. Headless executables (`idat`/`idat64`) must be available on your system.
  - Make sure `idat`/`idat64` is in your `PATH` (e.g., add your IDA install directory), or configure the executable path according to `ida-domain`’s documentation.
    ```
    export IDADIR="[IDA Installation Directory]"
    ```
  - Hex-Rays decompiler is optional but required for `decompile_function`.
- OS: Linux, Windows, or macOS supported by your IDA installation. The included examples were exercised on Linux.

## Installation
From source:

```bash
# With uv
uv venv
uv pip install -e .

# Or with pip/venv
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
```

From PyPI:

```bash
# With uv
uv add ida-domain-mcp

# Or with pip
pip install ida-domain-mcp
```

This installs `ida-domain-mcp` along with its runtime dependencies:
- `ida-domain` (database control via headless IDA)

Before running, verify IDA’s headless binary is accessible:

```bash
which idat64 || which idat
```

If not found, add the IDA folder to your `PATH` or use the configuration options provided by `ida-domain` to point to your IDA installation.

## Running the MCP server
Two transport modes are supported by the server entrypoint `ida-domain-mcp`:

1) stdio (default, for direct MCP client integration)
```bash
uv run ida-domain-mcp --transport stdio
```

2) HTTP SSE (useful with the MCP Inspector and remote clients)
```bash
uv run ida-domain-mcp --transport http://127.0.0.1:8744
# Server prints: MCP Server available at http://127.0.0.1:8744/sse
```

You can then connect with the MCP Inspector for quick exploration:

```bash
npx @modelcontextprotocol/inspector
# Point it to: http://127.0.0.1:8744/sse
```

## Testing
A simple dual-database test is provided:

```bash
# Start the server first (SSE mode)
uv run ida-domain-mcp --transport http://127.0.0.1:8744

# In another shell, run the test client
uv run ida_domain_mcp/tests/test_ida_mcp.py http://127.0.0.1:8744/sse
```

