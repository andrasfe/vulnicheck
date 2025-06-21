#!/usr/bin/env python
"""
MCP client that properly logs server startup and communication.
"""

import asyncio
import json
import os
import sys
from datetime import datetime


class MCPClientLogger:
    """MCP client focused on logging server behavior."""

    def __init__(self, log_to_file: bool = True):
        self.process = None
        self.log_to_file = log_to_file
        self.log_file = None

        if log_to_file:
            self.log_file = (
                f"mcp_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            )
            # Clear/create log file
            with open(self.log_file, "w") as f:
                f.write(f"MCP Test Session - {datetime.now()}\n")
                f.write("=" * 60 + "\n\n")

    def log(self, message: str, prefix: str = ""):
        """Log message with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if prefix:
            log_line = f"[{timestamp}] [{prefix}] {message}"
        else:
            log_line = f"[{timestamp}] {message}"

        print(log_line)

        if self.log_to_file and self.log_file:
            with open(self.log_file, "a") as f:
                f.write(log_line + "\n")

    async def start_and_monitor_server(self, duration: int = 10):
        """Start server and monitor its output for specified duration."""
        self.log("Starting VulniCheck MCP server...", "CLIENT")

        # Start server process
        self.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "vulnicheck.server",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "VULNICHECK_DEBUG": "true"},
        )

        self.log(f"Server process started (PID: {self.process.pid})", "CLIENT")

        # Create monitoring tasks
        stderr_task = asyncio.create_task(self._monitor_stderr())
        stdout_task = asyncio.create_task(self._monitor_stdout())
        interaction_task = asyncio.create_task(self._test_interaction())

        # Let it run for specified duration
        self.log(f"Monitoring server for {duration} seconds...", "CLIENT")
        await asyncio.sleep(duration)

        # Stop monitoring
        self.log("Stopping server...", "CLIENT")
        self.process.terminate()

        # Wait for tasks to complete
        await self.process.wait()
        stderr_task.cancel()
        stdout_task.cancel()
        interaction_task.cancel()

        self.log(f"Server stopped (exit code: {self.process.returncode})", "CLIENT")

    async def _monitor_stderr(self):
        """Monitor stderr output."""
        try:
            while True:
                line = await self.process.stderr.readline()
                if not line:
                    break
                decoded = line.decode().rstrip()
                if decoded:
                    self.log(decoded, "STDERR")
        except asyncio.CancelledError:
            pass

    async def _monitor_stdout(self):
        """Monitor stdout output."""
        try:
            buffer = b""
            while True:
                # Read available data
                chunk = await self.process.stdout.read(1024)
                if not chunk:
                    break

                buffer += chunk

                # Process complete lines
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    decoded = line.decode().rstrip()
                    if decoded:
                        self.log(decoded, "STDOUT")

                        # Try to parse as JSON
                        try:
                            data = json.loads(decoded)
                            self.log(
                                f"Parsed JSON: {json.dumps(data, indent=2)}", "JSON"
                            )
                        except json.JSONDecodeError:
                            pass  # Not JSON, skip parsing
        except asyncio.CancelledError:
            pass

    async def _test_interaction(self):
        """Test basic interaction after startup."""
        try:
            # Wait for server to start
            await asyncio.sleep(3)

            self.log("Sending initialize request...", "CLIENT")

            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "1.0",
                    "capabilities": {},
                    "clientInfo": {"name": "test-logger", "version": "1.0.0"},
                },
            }

            request_str = json.dumps(request) + "\n"
            self.log(f"Request: {json.dumps(request)}", "CLIENT")

            self.process.stdin.write(request_str.encode())
            await self.process.stdin.drain()

            # Wait a bit for response
            await asyncio.sleep(2)

            # Send another request
            self.log("Sending tools/list request...", "CLIENT")

            request2 = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

            request2_str = json.dumps(request2) + "\n"
            self.process.stdin.write(request2_str.encode())
            await self.process.stdin.drain()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.log(f"Error in interaction: {e}", "ERROR")


async def main():
    """Run the logger."""
    print("\n" + "=" * 60)
    print("MCP Server Startup and Communication Logger")
    print("=" * 60 + "\n")

    # Check environment
    if not os.environ.get("VIRTUAL_ENV"):
        print("⚠️  Warning: Not in virtual environment")

    # Create logger and run
    logger = MCPClientLogger(log_to_file=True)
    await logger.start_and_monitor_server(duration=10)

    if logger.log_file:
        print(f"\n📝 Full session log saved to: {logger.log_file}")
        print("\nLog preview:")
        print("-" * 60)

        # Show last 20 lines of log
        with open(logger.log_file) as f:
            lines = f.readlines()
            for line in lines[-20:]:
                print(line.rstrip())


if __name__ == "__main__":
    asyncio.run(main())
