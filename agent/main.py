"""OpenDeepHole Agent Daemon — WebSocket client that connects to the web server.

The agent connects to the server, receives task/stop/resume commands via WebSocket,
and pushes scan events and results back via HTTP POST.

Usage:
    python -m agent.main [OPTIONS]

    --server URL          Web server URL (overrides agent.yaml server_url)
    --name NAME           Agent display name (overrides agent.yaml agent_name)
    --config FILE         Path to config file (default: ./agent.yaml)

Examples:
    python -m agent.main
    python -m agent.main --server http://192.168.1.10:8000
    python -m agent.main --name "my-server" --config /etc/opendeephole/agent.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import sys
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent",
        description="OpenDeepHole agent daemon — connects to web server and executes scan tasks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--server", metavar="URL", help="Web server URL (overrides agent.yaml)")
    parser.add_argument("--name", metavar="NAME", help="Agent display name shown on web UI")
    parser.add_argument("--config", metavar="FILE", help="Path to agent.yaml config file")
    return parser.parse_args()


async def _handle_command(msg: dict, config, task_manager, reporter) -> dict | None:
    """Dispatch a command message from the server to the appropriate handler."""
    import agent.server as agent_server

    cmd_type = msg.get("type")

    if cmd_type == "task":
        from agent.updater import ensure_runtime_updated
        await ensure_runtime_updated(msg.get("agent_runtime_update"), msg)
        if msg.get("runtime_update_only"):
            post_update_command = msg.get("post_update_command")
            if isinstance(post_update_command, dict):
                return await _handle_command(post_update_command, config, task_manager, reporter)
            return None
        await agent_server.handle_task(
            scan_id=msg["scan_id"],
            project_path=msg["project_path"],
            code_scan_path=msg.get("code_scan_path"),
            checkers=msg.get("checkers", []),
            scan_name=msg.get("scan_name", ""),
            feedback_entries=msg.get("feedback_entries", []),
            checker_packages=msg.get("checker_packages", []),
        )
    elif cmd_type == "stop":
        await agent_server.handle_stop(msg["scan_id"])
    elif cmd_type == "resume":
        from agent.updater import ensure_runtime_updated
        await ensure_runtime_updated(msg.get("agent_runtime_update"), msg)
        await agent_server.handle_resume(
            scan_id=msg["scan_id"],
            project_path=msg.get("project_path"),
            code_scan_path=msg.get("code_scan_path"),
            checkers=msg.get("checkers"),
            scan_name=msg.get("scan_name"),
            feedback_entries=msg.get("feedback_entries"),
            checker_packages=msg.get("checker_packages"),
        )
    elif cmd_type == "fp_review":
        from agent.updater import ensure_runtime_updated
        await ensure_runtime_updated(msg.get("agent_runtime_update"), msg)
        await agent_server.handle_fp_review(
            scan_id=msg["scan_id"],
            review_id=msg["review_id"],
            project_path=msg["project_path"],
            vulnerabilities=msg.get("vulnerabilities", []),
            feedback_entries=msg.get("feedback_entries", []),
        )
    elif cmd_type == "fp_review_stop":
        await agent_server.handle_fp_review_stop(
            scan_id=msg["scan_id"],
            review_id=msg["review_id"],
        )
    elif cmd_type == "feedback_selection_update":
        await agent_server.handle_feedback_selection_update(
            scan_id=msg["scan_id"],
            feedback_entries=msg.get("feedback_entries", []),
        )
    elif cmd_type == "feedback_update":
        entry = msg.get("entry")
        if entry:
            from agent.fp_reviewer import update_local_feedback
            update_local_feedback(entry)
    elif cmd_type == "config":
        from agent.config import apply_network_env, apply_remote_config, save_config
        if msg.get("config"):
            apply_remote_config(config, msg["config"])
            apply_network_env(config)
            try:
                save_config(config)
                print("Config updated from server and persisted to agent.yaml")
            except Exception as e:
                print(f"Config updated from server (warning: failed to persist: {e})")
    elif cmd_type == "config_test":
        return await agent_server.handle_config_test(
            request_id=msg.get("request_id", ""),
            remote_config=msg.get("config") or {},
        )
    elif cmd_type == "skill_create":
        from agent.updater import ensure_runtime_updated
        await ensure_runtime_updated(msg.get("agent_runtime_update"), msg)
        return await agent_server.handle_skill_create(
            request_id=msg.get("request_id", ""),
            name=msg.get("name", ""),
            description=msg.get("description", ""),
            user_input=msg.get("input", ""),
            skill_creator_package=(
                msg.get("deephole_skill_creator_package")
                or msg.get("skill_creator_package")
                or {}
            ),
        )
    else:
        print(f"Unknown command type: {cmd_type!r}")
    return None


async def _ws_loop(config, task_manager, reporter) -> None:
    """WebSocket connection loop with automatic reconnect."""
    import websockets
    import agent.server as agent_server
    from agent.config import apply_network_env, apply_remote_config, remote_config_dict
    from agent.updater import compute_runtime_hash, load_pending_commands, pending_scan_snapshots

    name = config.agent_name or socket.gethostname()
    ws_url = config.server_url.replace("http://", "ws://").replace("https://", "wss://")
    ws_url = ws_url.rstrip("/") + "/api/agent/ws"
    ping_interval = _env_int("OPENDEEPHOLE_WS_PING_INTERVAL", 30)
    ping_timeout = _env_int("OPENDEEPHOLE_WS_PING_TIMEOUT", 120)
    heartbeat_interval = _env_int("OPENDEEPHOLE_AGENT_HEARTBEAT_INTERVAL", 30)
    watchdog_timeout = _env_int("OPENDEEPHOLE_AGENT_WATCHDOG_TIMEOUT", 120)

    reconnect_delay = 2

    while True:
        try:
            print(f"Connecting to {ws_url} ...")
            async with websockets.connect(
                ws_url,
                ping_interval=ping_interval,
                ping_timeout=ping_timeout,
            ) as ws:
                # Handshake
                hello_msg = {
                    "type": "hello",
                    "name": name,
                    "config": remote_config_dict(config),
                    "runtime_hash": compute_runtime_hash(),
                    "active_scans": task_manager.active_snapshots() + pending_scan_snapshots(),
                }
                if config.owner_token:
                    hello_msg["owner_token"] = config.owner_token
                await ws.send(json.dumps(hello_msg))

                welcome_raw = await asyncio.wait_for(ws.recv(), timeout=15.0)
                welcome = json.loads(welcome_raw)

                if welcome.get("type") != "welcome":
                    print(f"Unexpected handshake response: {welcome}")
                    continue

                agent_id = welcome["agent_id"]
                agent_server._agent_id = agent_id

                if welcome.get("config"):
                    from agent.config import save_config
                    apply_remote_config(config, welcome["config"])
                    apply_network_env(config)
                    try:
                        save_config(config)
                    except Exception as e:
                        print(f"Config received from server (warning: failed to persist: {e})")

                reconnect_delay = 2  # reset backoff on successful connect
                print(f"  Connected. Agent ID: {agent_id}")
                print()

                pending_commands = load_pending_commands(clear=True)

                loop = asyncio.get_running_loop()
                last_seen = loop.time()
                command_queue: asyncio.Queue[dict | None] = asyncio.Queue()

                async def _heartbeat() -> None:
                    while True:
                        await asyncio.sleep(heartbeat_interval)
                        await ws.send(json.dumps({"type": "heartbeat"}))

                async def _watchdog() -> None:
                    nonlocal last_seen
                    while True:
                        await asyncio.sleep(max(1, min(heartbeat_interval, 10)))
                        idle = loop.time() - last_seen
                        if idle > watchdog_timeout:
                            print(
                                f"Connection stale: no server message for {idle:.0f}s; reconnecting..."
                            )
                            await ws.close(code=4001, reason="agent heartbeat watchdog timeout")
                            return

                async def _command_worker() -> None:
                    while True:
                        msg = await command_queue.get()
                        if msg is None:
                            return
                        try:
                            response = await _handle_command(msg, config, task_manager, reporter)
                            if response:
                                await ws.send(json.dumps(response))
                        except Exception as e:
                            print(f"Error handling command: {e}")

                heartbeat_task = asyncio.create_task(_heartbeat())
                watchdog_task = asyncio.create_task(_watchdog())
                worker_task = asyncio.create_task(_command_worker())

                try:
                    for command in pending_commands:
                        await command_queue.put(command)
                    # Message loop
                    async for raw_msg in ws:
                        last_seen = loop.time()
                        try:
                            msg = json.loads(raw_msg)
                        except Exception as e:
                            print(f"Error parsing server message: {e}")
                            continue
                        if msg.get("type") == "heartbeat_ack":
                            continue
                        await command_queue.put(msg)
                finally:
                    heartbeat_task.cancel()
                    watchdog_task.cancel()
                    await command_queue.put(None)
                    worker_task.cancel()
                    for task in (heartbeat_task, watchdog_task, worker_task):
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass

        except Exception as e:
            print(f"Connection lost: {e}. Reconnecting in {reconnect_delay}s...")
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60)


async def _main() -> None:
    args = _parse_args()

    # Load config
    from agent.config import apply_network_env, load_config
    config_path = Path(args.config) if args.config else None
    config = load_config(config_path)

    # Apply CLI overrides
    if args.server:
        config.server_url = args.server
    if args.name:
        config.agent_name = args.name

    # Apply no_proxy early so httpx respects it
    apply_network_env(config)

    name = config.agent_name or socket.gethostname()

    print("OpenDeepHole Agent Daemon")
    print(f"  Name    : {name}")
    print(f"  Server  : {config.server_url}")
    print()

    from agent.reporter import Reporter
    from agent.task_manager import TaskManager
    import agent.server as agent_server

    reporter = Reporter(config.server_url)
    task_manager = TaskManager()

    # Inject globals into agent.server module
    agent_server._config = config
    agent_server._reporter = reporter
    agent_server._task_manager = task_manager

    try:
        await _ws_loop(config, task_manager, reporter)
    finally:
        await reporter.close()


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
