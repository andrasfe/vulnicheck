#!/usr/bin/env python
"""Quick test to check a single package for vulnerabilities."""

import asyncio
import json
import sys


async def quick_test():
    """Quick vulnerability test."""
    print("Starting VulniCheck server...")

    # Start server
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "vulnicheck.server",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Monitor stderr
    async def log_stderr():
        while True:
            line = await process.stderr.readline()
            if not line:
                break
            print(f"[SERVER] {line.decode().rstrip()}")

    asyncio.create_task(log_stderr())
    await asyncio.sleep(2)

    try:
        # Initialize
        print("\n1. Initializing...")
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "1.0",
                "capabilities": {},
                "clientInfo": {"name": "quick-test", "version": "1.0"},
            },
        }

        process.stdin.write((json.dumps(init_req) + "\n").encode())
        await process.stdin.drain()

        response = await process.stdout.readline()
        print(f"Response: {response.decode().rstrip()}")

        # Send initialized notification
        init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        process.stdin.write((json.dumps(init_notif) + "\n").encode())
        await process.stdin.drain()
        await asyncio.sleep(0.5)

        # Check django
        print("\n2. Checking django 2.2.0 for vulnerabilities...")
        check_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "check_package_vulnerabilities",
                "arguments": {
                    "package_name": "django",
                    "version": "2.2.0",
                    "include_details": False,
                },
            },
        }

        process.stdin.write((json.dumps(check_req) + "\n").encode())
        await process.stdin.drain()

        response = await process.stdout.readline()
        result = json.loads(response.decode())

        if "result" in result and "content" in result["result"]:
            print("\n" + "=" * 60)
            print("VULNERABILITY REPORT:")
            print("=" * 60)
            for content in result["result"]["content"]:
                if content.get("type") == "text":
                    print(content["text"])
        else:
            print(f"Error: {result}")

    finally:
        process.terminate()
        await process.wait()
        print("\nTest completed.")


if __name__ == "__main__":
    asyncio.run(quick_test())
