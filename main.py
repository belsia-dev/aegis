#!/usr/bin/env python3

import asyncio
import argparse
import signal
import sys
from pathlib import Path

from core.config import Config
from core.logger import init_logging, get_logger

from detection.engine import DetectionEngine
from monitors.log_monitor import LogMonitor
from monitors.process_monitor import ProcessMonitor
from monitors.persistence_monitor import PersistenceMonitor
from monitors.traffic_monitor import TrafficMonitor
from monitors.script_guard import ScriptGuard
from integrations.abuseipdb import AbuseIPDBClient
from integrations.ipinfo import IPInfoClient
from response.actions import ResponseEngine
from api.server import WebServer

async def _shutdown(loop, tasks, firewall=None, detection=None):
    logger = get_logger("main")
    logger.info("AEGIS shutdown initiated")
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    if detection is not None:
        detection.flush()
    if firewall is not None:
        try:
            await firewall.flush_chain()
            logger.info("Firewall chain flushed")
        except Exception as exc:
            logger.warning("Could not flush firewall", extra={"error": str(exc)})
    loop.stop()
    logger.info("AEGIS stopped cleanly")

async def main(config_path: str):
    config = Config(config_path)

    init_logging(
        log_file=config.log_file,
        audit_file=config.audit_file,
        level=config.log_level,
    )
    logger = get_logger("main")
    logger.info("AEGIS starting", extra={"config": config_path})

    if config.dry_run:
        logger.warning("DRY-RUN mode — firewall rules will NOT be applied")

    abuseipdb   = AbuseIPDBClient(config)
    ipinfo      = IPInfoClient(config)
    detection   = DetectionEngine(config, abuseipdb, ipinfo)
    responder   = ResponseEngine(config, detection)

    traffic     = TrafficMonitor(config, detection)
    script_guard = ScriptGuard(config, detection)

    web_server  = WebServer(
        config, detection, responder,
        traffic=traffic,
        script_guard=script_guard,
    )

    log_monitor         = LogMonitor(config, detection)
    process_monitor     = ProcessMonitor(config, detection)
    persistence_monitor = PersistenceMonitor(config, detection)

    detection.set_response_callback(responder.handle_alert)
    await responder._firewall.start()

    loop = asyncio.get_running_loop()
    tasks = [
        asyncio.create_task(log_monitor.run(),           name="log_monitor"),
        asyncio.create_task(process_monitor.run(),       name="proc_monitor"),
        asyncio.create_task(persistence_monitor.run(),   name="persist_monitor"),
        asyncio.create_task(traffic.run(),               name="traffic_monitor"),
        asyncio.create_task(script_guard.run(),          name="script_guard"),
        asyncio.create_task(web_server.run(),            name="web_server"),
        asyncio.create_task(responder.unban_loop(),      name="unban_loop"),
    ]

    firewall = responder._firewall

    def _sig():
        asyncio.ensure_future(
            _shutdown(loop, tasks, firewall, detection), loop=loop
        )

    loop.add_signal_handler(signal.SIGINT,  _sig)
    loop.add_signal_handler(signal.SIGTERM, _sig)

    logger.info(
        "AEGIS active — all modules started",
        extra={
            "web_ui":   f"http://{config.api('host','127.0.0.1')}:{config.api('port',8731)}",
            "dry_run":  config.dry_run,
            "firewall": config.firewall_backend,
        },
    )

    await asyncio.gather(*tasks, return_exceptions=True)

    await abuseipdb.close()
    await ipinfo.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="aegis",
        description="AEGIS — Adaptive Engine for Guardian Intelligence and Security")
    parser.add_argument("-c", "--config", default="/etc/aegis/config.yaml", metavar="PATH")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--version", action="version", version="AEGIS")
    args = parser.parse_args()

    if not Path(args.config).exists():
        print(f"\n[AEGIS] ERROR: Config not found: {args.config}")
        print("        sudo cp config.example.yaml /etc/aegis/config.yaml\n")
        sys.exit(1)

    if args.dry_run:
        import os
        os.environ["AEGIS_DRY_RUN"] = "1"

    try:
        asyncio.run(main(args.config))
    except KeyboardInterrupt:
        pass
