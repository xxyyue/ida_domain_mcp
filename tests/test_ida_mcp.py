"""Dual-database parallel analysis test script

Example startup:
	uv run ida-domain-mcp --transport http://127.0.0.1:8744
	uv run tests/test_ida_mcp.py http://127.0.0.1:8744/sse

Test objectives:
1. Connect to the ida-domain-mcp MCP Server (SSE transport)
2. Use open_database to open two databases corresponding to different project_name values (using different binaries)
3. Call tools (idb_meta / entrypoints / list_funcs, etc.) to verify they don't interfere with each other
4. Compare the metadata and entry point lists of the two databases for differences
5. Close both databases

Notes:
	- Tool results returned by the server are JSON strings and need to be decoded.
	- If analysis is not finished, function lists may be temporarily empty; retry as needed.
"""

import asyncio
import importlib
import json
import os
import sys
import time
from typing import Any, Dict, Optional, Callable

DEFAULT_SSE_URL = "http://127.0.0.1:8744/sse"



async def _call_tool(server: Any, tool_name: str, arguments: Optional[Dict[str, Any]] = None):
	"""Generic tool call, compatible with different client method names."""
	arguments = arguments or {}
	for meth in ("call_tool", "execute_tool"):
		fn = getattr(server, meth, None)
		if callable(fn):
			return await fn(tool_name, arguments)
	client = getattr(server, "client", None)
	if client is not None:
		for meth in ("call_tool", "execute_tool", "tools_call"):
			fn = getattr(client, meth, None)
			if callable(fn):
				try:
					return await fn(tool_name, arguments)
				except TypeError:
					payload = {"name": tool_name, "arguments": arguments}
					return await fn(payload)
	raise RuntimeError(f"Could not find tool call method on server: {tool_name}")


async def _list_tools(server: Any):
	for meth in ("list_tools", "get_tools"):
		fn = getattr(server, meth, None)
		if callable(fn):
			return await fn()
	client = getattr(server, "client", None)
	if client is not None:
		for meth in ("list_tools", "get_tools", "tools_list"):
			fn = getattr(client, meth, None)
			if callable(fn):
				return await fn()
	return None



def _decode_json_field(payload: Any) -> Any:
	"""Try to extract 'business data' from MCP returned objects.
	Prefer structuredContent.result, then content text, then parse string.
	"""
	# 1) Handle object form (e.g., CallToolResult)
	try:
		sc = getattr(payload, "structuredContent", None)
		if isinstance(sc, dict) and "result" in sc:
			data = sc.get("result")
			if isinstance(data, str):
				try:
					return json.loads(data)
				except Exception:
					return data
			return data
	except Exception:
		pass

	# 2) Try content list (TextContent...)
	try:
		content = getattr(payload, "content", None)
		if isinstance(content, list) and content:
			# Try concatenating text
			texts = []
			for item in content:
				# item may be object or dict
				text = None
				if isinstance(item, dict):
					text = item.get("text")
				else:
					text = getattr(item, "text", None)
				if isinstance(text, str):
					texts.append(text)
			if texts:
				joined = "\n".join(texts)
				try:
					return json.loads(joined)
				except Exception:
					return joined
	except Exception:
		pass

	# 3) Directly handle dict structures
	if isinstance(payload, dict):
		# common wrapper {"result": "{...json...}"}
		if "result" in payload:
			val = payload["result"]
			if isinstance(val, str):
				try:
					return json.loads(val)
				except Exception:
					return val
			return val
		return payload

	# 4) String JSON
	if isinstance(payload, str):
		try:
			return json.loads(payload)
		except Exception:
			return payload

	# 5) Other types returned as-is (let caller handle/print)
	return payload



async def _retry_tool(server: Any, tool_name: str, args: Dict[str, Any], predicate: Callable[[Any], bool], retries: int = 5, delay: float = 1.0):
	"""Tool call with retries until predicate returns True or attempts exhausted."""
	last = None
	for _ in range(retries):
		last = await _call_tool(server, tool_name, args)
		decoded = _decode_json_field(last)
		if predicate(decoded):
			return decoded
		await asyncio.sleep(delay)
	return _decode_json_field(last)


async def run_dual_database_test(sse_url: str):
	# 1. Dynamically import MCP client
	try:
		mcp_mod = importlib.import_module("agents.mcp")
		MCPServerSse = getattr(mcp_mod, "MCPServerSse")
	except Exception:
		print("Unable to import agents.mcp. Please install the openai-agents package.")
		# do not import agents.mcp when the VPN proxy is enabled
		sys.exit(1)

	print(f"Connecting to MCP server: {sse_url}")
	server = MCPServerSse(
		params={"url": sse_url},
		cache_tools_list=True,
		name="ida-domain-mcp",
		client_session_timeout_seconds=120,
	)

	await server.connect()
	print("Connected.")

	tools = await _list_tools(server)
	if tools is None:
		print("Unable to list tools, continuing with the rest of the tests.")
	else:
		print("Tools list (truncated/formatted):")
		try:
			print(json.dumps(tools, ensure_ascii=False, indent=2, default=str)[:2000])
		except TypeError:
			print(str(tools))

	# 2. Open two databases (different project names, different binaries)
	base_dir = os.path.dirname(__file__)
	bin_a = os.path.join(base_dir, "challenge", "binaries", "device_main")
	bin_b = os.path.join(base_dir, "challenge", "binaries", "secure_check.so")
	if not os.path.exists(bin_a) or not os.path.exists(bin_b):
		print(f"Missing test binaries: {bin_a} or {bin_b}")
		await server.cleanup()
		sys.exit(1)

	proj_a = "projA"
	proj_b = "projB"

	print(f"Opening database: {proj_a} -> {bin_a}")
	r_open_a = _decode_json_field(await _call_tool(server, "open_database", {
		"project_name": proj_a,
		"db_path": bin_a,
		"auto_analysis": True,
		"new_database": False,
		"save_on_close": False,
	}))
	print("Result:", r_open_a)

	print(f"Opening database: {proj_b} -> {bin_b}")
	r_open_b = _decode_json_field(await _call_tool(server, "open_database", {
		"project_name": proj_b,
		"db_path": bin_b,
		"auto_analysis": True,
		"new_database": False,
		"save_on_close": False,
	}))
	print("Result:", r_open_b)

	# 3. Obtain metadata (analysis may not be finished, retry until some function/segment info present)
	print("Fetching metadata for project A...")
	meta_a = await _retry_tool(server, "idb_meta", {"project_name": proj_a}, lambda d: isinstance(d, dict), retries=5)
	print("metaA:", json.dumps(meta_a, ensure_ascii=False, indent=2)[:1500])

	print("Fetching metadata for project B...")
	meta_b = await _retry_tool(server, "idb_meta", {"project_name": proj_b}, lambda d: isinstance(d, dict), retries=5)
	print("metaB:", json.dumps(meta_b, ensure_ascii=False, indent=2)[:1500])

	# 4. Get entry point lists and compare
	print("Fetching entry points for project A...")
	entries_a_raw = await _call_tool(server, "entrypoints", {"project_name": proj_a})
	entries_a = _decode_json_field(entries_a_raw)
	print("entriesA:", entries_a)

	print("Fetching entry points for project B...")
	entries_b_raw = await _call_tool(server, "entrypoints", {"project_name": proj_b})
	entries_b = _decode_json_field(entries_b_raw)
	print("entriesB:", entries_b)

	# 5. Get function list (first 5) for comparison
	def _func_list_pred(d: Any) -> bool:
		# Accept legacy dict wrappers or new list[Page] format from list_funcs
		if isinstance(d, dict):
			for k in ("functions", "items", "result"):
				v = d.get(k)
				if isinstance(v, list) and len(v) > 0:
					return True
		if isinstance(d, list) and len(d) > 0:
			# Each page is a dict with 'items'
			for page in d:
				if isinstance(page, dict):
					items = page.get("items")
					if isinstance(items, list) and len(items) > 0:
						return True
		return False

	print("Listing project A functions (retry)...")
	list_a = await _retry_tool(server, "list_funcs", {"project_name": proj_a, "queries": {"offset": 0, "count": 5}}, _func_list_pred, retries=6)
	print("funcsA:", json.dumps(list_a, ensure_ascii=False, indent=2)[:1200])

	print("Listing project B functions (retry)...")
	list_b = await _retry_tool(server, "list_funcs", {"project_name": proj_b, "queries": {"offset": 0, "count": 5}}, _func_list_pred, retries=6)
	print("funcsB:", json.dumps(list_b, ensure_ascii=False, indent=2)[:1200])

	# 6. Basic difference checks
	diff_flags = []
	if meta_a == meta_b:
		diff_flags.append("Metadata identical")
	if entries_a == entries_b:
		diff_flags.append("Entry point lists identical")
	if list_a == list_b:
		diff_flags.append("Function lists identical")

	if diff_flags:
		print("[WARNING] High similarity between the two database results: " + "; ".join(diff_flags))
	else:
		print("Databases differ; test passed.")

	# 7. Close databases
	print("Closing project A database ...")
	close_a = _decode_json_field(await _call_tool(server, "close_database", {"project_name": proj_a, "save": False}))
	print("closeA:", close_a)
	print("Closing project B database ...")
	close_b = _decode_json_field(await _call_tool(server, "close_database", {"project_name": proj_b, "save": False}))
	print("closeB:", close_b)

	await server.cleanup()
	print("Connections cleaned up.")

	if diff_flags:
		sys.exit(2)


def main():
	url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SSE_URL
	asyncio.run(run_dual_database_test(url))


if __name__ == "__main__":
	main()

