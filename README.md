# ida-domain-mcp

A headless Model Context Protocol (MCP) server for IDA Pro built on top of `ida-domain`. It lets AI agents (or any MCP client) open and analyze IDA databases on demand — without launching the IDA manully — and control common reverse engineering workflows programmatically.

Unlike GUI-centric approaches, ida-domain-mcp spins up per-project worker processes on demand and loads binaries via an MCP tool call during the agent's workflow. You don't have to pre-load binaries at MCP server startup, and once configured, the whole flow can run fully automatically without human interaction.

## Example

![demo](assets/demo.png)

## Why it's different

- Headless by design: No dependency on the IDA graphical UI. Uses IDA's headless runners underneath via `ida-domain`.
- On-demand database loading: Call the `open_database` MCP tool at any time during the agent session to load a binary or IDB; no manual preloading required.
- Multi-project isolation: Each `project_name` runs in its own worker process; multiple binaries can be analyzed concurrently without interfering with each other.

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
- Address parameters are accepted as integers or hex strings by MCP entry points and are converted internally; results commonly encode addresses as hex strings.

## Requirements

- Python: 3.11+
- IDA: IDA Pro 9.1.0 or later installed.
- uv is recommended for Python package and project management. See [uv documentation](https://docs.astral.sh/uv/) for installation instructions.

## Environment Variables

Configure the executable path according to [`ida-domain`'s documentation](https://ida-domain.docs.hex-rays.com/getting_started/#step-3-verify-installation).
```sh
export IDADIR="[IDA Installation Directory]"
```
Headless executables (`idat`/`idat64`) must be available in the specified IDA installation directory.

## Installation

**Make sure to set up the environment variable as described above before running the MCP server.**

### Run with `uvx`

The simplest way to run the MCP server without installing anything is via `uvx`:

```sh
uvx ida-domain-mcp --transport http://127.0.0.1:8744
```

### Install from PyPI

You can install the package as a dependency of your project from PyPI:

```sh
# With uv
uv init
uv add ida-domain-mcp
# Or with pip
pip install ida-domain-mcp
```

## Running the MCP server

Two transport modes are supported by the server entrypoint `ida-domain-mcp`:

1. stdio (default, for direct MCP client integration)
    ```sh
    uv run ida-domain-mcp --transport stdio
    ```

2. SSE or Streamable HTTP (useful with the MCP Inspector and remote clients)
    ```sh
    # sse at http://127.0.0.1:8744/sse
    uv run ida-domain-mcp --transport http://127.0.0.1:8744
    # streamable http at http://127.0.0.1:8744/mcp
    uv run ida-domain-mcp --transport http://127.0.0.1:8744 --streamable-http
    ```

    You can then connect with the MCP Inspector for quick exploration:

    ```sh
    npx @modelcontextprotocol/inspector
    # Point it to: http://127.0.0.1:8744/sse (SSE) or http://127.0.0.1:8744/mcp (Streamable HTTP)
    ```

## Testing

Clone the repository and install the dependencies:

```sh
git clone https://github.com/xxyyue/ida_domain_mcp
cd ida_domain_mcp
uv sync
```

A simple dual-database test is provided:

```sh
# Start the server first (SSE mode)
uv run ida-domain-mcp --transport http://127.0.0.1:8744

# In another shell, run the test client
uv run ida_domain_mcp/tests/test_ida_mcp.py http://127.0.0.1:8744/sse
# Or, run the test agent
echo "OPENAI_API_KEY=sk-..." > .env
uv run tests/agent.py
```
