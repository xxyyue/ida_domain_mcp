import asyncio
import os
import dotenv
from agents import Agent, RunConfig, Runner, ModelSettings
from agents.mcp import MCPServerStdio, MCPServerSse
from colorama import Fore, Style
from openai import AsyncOpenAI

from agents import set_tracing_disabled
set_tracing_disabled(True)

dotenv.load_dotenv()

API_KEY = os.getenv("OPENAI_API_KEY")
BASE_URL = os.getenv("OPENAI_BASE_URL")
OPENAI_DEFAULT_MODEL = os.getenv("OPENAI_DEFAULT_MODEL")

ida_domain_tool = {
      "name": "ida-domain-mcp",
      "url": "http://127.0.0.1:8744/sse",
      "cache_tools_list": True
    }

query = """
You task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information.

Please:
- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments with your findings
- NEVER convert number bases yourself. Use the convert_number MCP tool if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
- When you find a solution, prompt to me for feedback with the password you found
- Summarize your findings and the steps you took to reach the solution

Files you may need:
tests/binaries/crackme03.elf
"""

async def main():

    # mcp tools setup
    mcp_server = MCPServerSse(
        params={"url": ida_domain_tool["url"]},
        cache_tools_list=ida_domain_tool.get('cache_tools_list', True),
        name=ida_domain_tool['name'],
        client_session_timeout_seconds=600
    )
    try:
        await mcp_server.connect()
        print(f"{Fore.GREEN}Connected to MCP server: {mcp_server.name}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Failed to connect to MCP server {mcp_server.name}: {e}{Style.RESET_ALL}")
        print("Please run the MCP server before executing this script.")
        print("  uv run ida-domain-mcp --transport http://127.0.0.1:8744")
        return
    
    # create agent
    try:
        agent = Agent(
            name="ida-domain-agent",
            mcp_servers=[mcp_server],
            instructions="You are an expert in IDA Pro and domain analysis. Use the MCP tools to assist in your tasks.",
            model_settings=ModelSettings(
                temperature=0.6,
                tool_choice="auto",
                parallel_tool_calls=False,
                truncation="auto"
            )
        )

        print(f"{Fore.CYAN}\nProcessing query: {Fore.WHITE}{query}{Style.RESET_ALL}\n")
        result = await Runner.run(
            agent,
            input=query,
            max_turns=30,
            run_config=RunConfig(
                trace_include_sensitive_data=True,
                handoff_input_filter=None
            )
        )
        print(f"{Fore.YELLOW}Agent Result: {result}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Error during agent run: {e}{Style.RESET_ALL}")
    finally:
        # Cleanup
        try:
            await mcp_server.cleanup()
            print(f"{Fore.GREEN}Cleanup completed for {mcp_server.name}.{Style.RESET_ALL}", flush=True)
        except Exception as e:
            print(f"{Fore.RED}Failed to cleanup {mcp_server.name}.{Style.RESET_ALL}", flush=True)

        print(f"{Fore.YELLOW}MCP server resource cleanup complete.{Style.RESET_ALL}") 

if __name__ == "__main__":

    # validate env vars
    if not API_KEY:
        raise ValueError("API key not set")
    if not BASE_URL:
        raise ValueError("API base URL not set")
    if not OPENAI_DEFAULT_MODEL:
        raise ValueError("Model name not set")
    
    # validate connection
    _ = AsyncOpenAI(
        base_url=BASE_URL,
        api_key=API_KEY
    )
    
    # run main
    asyncio.run(main())
