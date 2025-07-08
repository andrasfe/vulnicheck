#!/usr/bin/env python
"""
Simple MCP client for testing server startup and basic communication.
"""

import asyncio
import json
import os
import sys
from datetime import datetime


class SimpleMCPClient:
    """Minimal MCP client for testing."""

    def __init__(self):
        self.process = None
        self.log_file = f"mcp_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    def log(self, message: str):
        """Log message to console and file."""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        log_line = f"[{timestamp}] {message}"
        print(log_line)
        with open(self.log_file, "a") as f:
            f.write(log_line + "\n")

    async def start_server(self):
        """Start the MCP server and capture all output."""
        self.log("🚀 Starting VulniCheck MCP server...")

        # Start server process
        self.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "vulnicheck.server",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        self.log(f"✅ Server process started (PID: {self.process.pid})")

        # Create tasks to log stdout and stderr
        asyncio.create_task(self._log_stream(self.process.stdout, "STDOUT"))
        asyncio.create_task(self._log_stream(self.process.stderr, "STDERR"))

        # Give server time to start
        await asyncio.sleep(2)

    async def _log_stream(self, stream, name):
        """Log output from a stream."""
        while True:
            line = await stream.readline()
            if not line:
                break
            decoded = line.decode().rstrip()
            self.log(f"[{name}] {decoded}")

    async def send_json_rpc(self, method: str, params: dict | None = None):
        """Send a JSON-RPC request."""
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}

        request_str = json.dumps(request) + "\n"
        self.log(f"📤 Sending: {json.dumps(request, separators=(',', ':'))}")

        self.process.stdin.write(request_str.encode())
        await self.process.stdin.drain()

        # Try to read response
        try:
            response_line = await asyncio.wait_for(
                self.process.stdout.readline(), timeout=5.0
            )
            if response_line:
                response = json.loads(response_line.decode())
                self.log(f"📥 Response: {json.dumps(response, separators=(',', ':'))}")
                return response
        except asyncio.TimeoutError:
            self.log("⏱️  Timeout waiting for response")
        except json.JSONDecodeError as e:
            self.log(f"❌ JSON decode error: {e}")
        except Exception as e:
            self.log(f"❌ Error reading response: {e}")

        return None

    async def test_basic_communication(self):
        """Test basic MCP communication."""
        self.log("\n🧪 Testing basic communication...")

        # Test 1: Initialize
        self.log("\n1️⃣ Testing initialize...")
        await self.send_json_rpc(
            "initialize",
            {
                "protocolVersion": "1.0",
                "capabilities": {},
                "clientInfo": {"name": "simple-test-client", "version": "1.0.0"},
            },
        )

        # Test 2: List tools
        self.log("\n2️⃣ Testing tools/list...")
        await self.send_json_rpc("tools/list")

        # Test 3: Call a tool
        self.log("\n3️⃣ Testing tools/call...")
        await self.send_json_rpc(
            "tools/call",
            {
                "name": "check_package_vulnerabilities",
                "arguments": {"package_name": "requests", "version": "2.31.0"},
            },
        )

    async def stop_server(self):
        """Stop the server gracefully."""
        self.log("\n🛑 Stopping server...")

        if self.process:
            self.process.terminate()
            await self.process.wait()
            self.log(f"✅ Server stopped (exit code: {self.process.returncode})")

    async def run(self):
        """Run the full test."""
        try:
            await self.start_server()
            await self.test_basic_communication()
        except Exception as e:
            self.log(f"❌ Fatal error: {e}")
            import traceback

            self.log(traceback.format_exc())
        finally:
            await self.stop_server()
            self.log(f"\n📝 Full log saved to: {self.log_file}")


async def main():
    """Main entry point."""
    print("=" * 60)
    print("Simple MCP Client Test")
    print("=" * 60)

    client = SimpleMCPClient()
    await client.run()


if __name__ == "__main__":
    # Check environment
    if not os.environ.get("VIRTUAL_ENV"):
        print("⚠️  Warning: Not in virtual environment")
        print("   Run: source .venv/bin/activate")
        print()

    # Run test
    asyncio.run(main())
