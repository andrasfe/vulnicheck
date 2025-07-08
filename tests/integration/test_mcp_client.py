"""
Test MCP client that connects to VulniCheck server and logs interactions.
"""

import asyncio
import json
import os
import sys
from typing import Any

# Add parent directory to path to import vulnicheck modules
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


class MCPTestClient:
    """Test client for MCP server communication."""

    def __init__(self, server_command: str):
        self.server_command = server_command
        self.process = None
        self.reader = None
        self.writer = None
        self.message_id = 0

    async def start_server(self):
        """Start the MCP server subprocess."""
        print("🚀 Starting VulniCheck MCP server...")

        # Start server process
        self.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "vulnicheck.server",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        self.reader = self.process.stdout
        self.writer = self.process.stdin

        # Read and log stderr output in background
        asyncio.create_task(self._log_stderr())

        # Give server time to start
        await asyncio.sleep(1)
        print("✅ Server process started")

    async def _log_stderr(self):
        """Log stderr output from server."""
        while True:
            line = await self.process.stderr.readline()
            if not line:
                break
            print(f"[SERVER] {line.decode().rstrip()}")

    async def send_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send JSON-RPC request to server."""
        self.message_id += 1

        request = {
            "jsonrpc": "2.0",
            "id": self.message_id,
            "method": method,
            "params": params or {},
        }

        # Send request
        request_str = json.dumps(request) + "\n"
        print(f"\n📤 Sending request: {method}")
        print(f"   Params: {json.dumps(params, indent=2) if params else 'None'}")

        if not self.writer or not self.reader:
            raise RuntimeError("Server not started")

        self.writer.write(request_str.encode())
        await self.writer.drain()

        # Read response
        response_line = await self.reader.readline()
        response = json.loads(response_line.decode())

        print("📥 Received response:")
        print(f"   {json.dumps(response, indent=2)}")

        return response

    async def initialize(self):
        """Initialize the MCP connection."""
        print("\n🔧 Initializing MCP connection...")

        response = await self.send_request(
            "initialize",
            {
                "protocolVersion": "1.0",
                "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        )

        if "result" in response:
            print("✅ Initialization successful")
            print(f"   Server: {response['result'].get('serverInfo', {})}")
            print(
                f"   Capabilities: {list(response['result'].get('capabilities', {}).keys())}"
            )
        else:
            print("❌ Initialization failed")

        return response

    async def list_tools(self):
        """List available tools."""
        print("\n🔍 Listing available tools...")

        response = await self.send_request("tools/list")

        if "result" in response and "tools" in response["result"]:
            tools = response["result"]["tools"]
            print(f"✅ Found {len(tools)} tools:")
            for tool in tools:
                print(f"   - {tool['name']}: {tool['description']}")
        else:
            print("❌ Failed to list tools")

        return response

    async def call_tool(self, name: str, arguments: dict[str, Any]):
        """Call a specific tool."""
        print(f"\n🛠️  Calling tool: {name}")

        response = await self.send_request(
            "tools/call", {"name": name, "arguments": arguments}
        )

        if "result" in response:
            print("✅ Tool call successful")
            if "content" in response["result"]:
                for content in response["result"]["content"]:
                    if content.get("type") == "text":
                        print("\n📄 Result:")
                        print(content["text"])
        else:
            print(f"❌ Tool call failed: {response.get('error', 'Unknown error')}")

        return response

    async def close(self):
        """Close the connection and stop the server."""
        print("\n🛑 Closing connection...")

        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()

        if self.process:
            self.process.terminate()
            await self.process.wait()

        print("✅ Connection closed")


async def run_test_client():
    """Run the test client with various operations."""
    client = MCPTestClient("vulnicheck")

    try:
        # Start server
        await client.start_server()

        # Initialize connection
        await client.initialize()

        # List available tools
        await client.list_tools()

        # Test 1: Check a known vulnerable package
        print("\n" + "=" * 60)
        print("TEST 1: Check known vulnerable package")
        print("=" * 60)
        await client.call_tool(
            "check_package_vulnerabilities",
            {"package_name": "django", "version": "2.2.0", "include_details": False},
        )

        # Test 2: Check a safe package
        print("\n" + "=" * 60)
        print("TEST 2: Check safe package")
        print("=" * 60)
        await client.call_tool(
            "check_package_vulnerabilities",
            {"package_name": "requests", "version": "2.31.0"},
        )

        # Test 3: Get CVE details
        print("\n" + "=" * 60)
        print("TEST 3: Get CVE details")
        print("=" * 60)
        await client.call_tool("get_cve_details", {"cve_id": "CVE-2021-45115"})

        # Test 4: Scan a sample requirements file
        print("\n" + "=" * 60)
        print("TEST 4: Scan requirements file")
        print("=" * 60)

        # Create a sample requirements.txt
        sample_requirements = """django==2.2.0
requests==2.31.0
numpy==1.19.0
flask==1.0.0
"""
        with open("/tmp/test_requirements.txt", "w") as f:
            f.write(sample_requirements)

        await client.call_tool(
            "scan_dependencies",
            {"file_path": "/tmp/test_requirements.txt", "include_details": True},
        )

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()

    finally:
        # Clean up
        await client.close()
        if os.path.exists("/tmp/test_requirements.txt"):
            os.remove("/tmp/test_requirements.txt")


def main():
    """Main entry point."""
    print("🧪 VulniCheck MCP Test Client")
    print("=" * 60)

    # Check if we're in virtual environment
    if not os.environ.get("VIRTUAL_ENV"):
        print("⚠️  Warning: Not running in virtual environment")
        print("   Consider activating the venv first: source .venv/bin/activate")
        print()

    # Run the async test client
    asyncio.run(run_test_client())

    print("\n✅ Test client completed")


if __name__ == "__main__":
    main()
