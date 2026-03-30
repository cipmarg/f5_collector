#!/usr/bin/env python3
import argparse
import getpass
import io
import json
import logging
import os
import re
import shlex
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import paramiko
import textfsm
import yaml
from sqlalchemy import create_engine


LOG = logging.getLogger("f5_jump_collector")


DEFAULT_COMMANDS = [
    {
        "name": "sys_version",
        "method": "ssh_device",
        "command": 'tmsh -q -c "show sys version"',
        "template": "textfsm_template_show_sys_version.textfsm",
        "table": "sys_versions",
    },
    {
        "name": "failover_status",
        "method": "ssh_device",
        "command": 'tmsh -q -c "show cm failover-status"',
        "template": "textfsm_template_show_cm_failover-status.textfsm",
        "table": "failover_status",
    },
    {
        "name": "ltm_node",
        "method": "ssh_device",
        "command": 'tmsh -q -c "show ltm node"',
        "template": "textfsm_template_show_ltm_node.textfsm",
        "table": "ltm_nodes",
    },
    {
        "name": "ltm_virtual_raw",
        "method": "ssh_device",
        "command": 'tmsh -q -c "show ltm virtual raw field-fmt"',
        "template": "textfsm_template_show_ltm_virtual_raw_field-fmt.textfsm",
        "table": "ltm_virtual_stats",
    },
    {
        "name": "sys_provision_asm",
        "method": "ssh_device",
        "command": 'tmsh -q -c "show sys provision asm"',
        "template": "textfsm_template_show_sys_provision_asm.textfsm",
        "table": "sys_provision_asm",
    },
    {
        "name": "list_ltm_virtual",
        "method": "ssh_device",
        "command": 'tmsh -q -c "list ltm virtual"',
        "template": "textfsm_template_list_ltm_virtual.textfsm",
        "table": "ltm_virtuals",
    },
    {
        "name": "list_sys_crypto_key",
        "method": "ssh_device",
        "command": 'tmsh -q -c "list sys crypto key"',
        "template": "textfsm_template_list_sys_crypto_key.textfsm",
        "table": "crypto_keys",
    },
    {
        "name": "list_sys_file_ssl_cert_all_properties",
        "method": "ssh_device",
        "command": 'tmsh -q -c "list sys file ssl-cert all-properties"',
        "template": "textfsm_template_list_sys_file_ssl-cert_all-properties.textfsm",
        "table": "ssl_certs",
    },
]


@dataclass
class CommandResult:
    name: str
    rc: int
    output: str
    error: str
    started_at: str
    ended_at: str


class JumpSession:
    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.client: Optional[paramiko.SSHClient] = None
        self.chan: Optional[paramiko.Channel] = None
        self.prompt = "__JUMP_PROMPT__# "

    def connect(self) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            look_for_keys=True,
            allow_agent=True,
        )
        chan = client.invoke_shell(width=240, height=1000)
        chan.settimeout(1.0)
        self.client = client
        self.chan = chan
        self._bootstrap_shell()
        LOG.info("Connected to jump host %s", self.host)

    def close(self) -> None:
        try:
            if self.chan:
                self.chan.close()
        finally:
            if self.client:
                self.client.close()

    def _bootstrap_shell(self) -> None:
        bootstrap = r'''
export PS1="__JUMP_PROMPT__# "
export PROMPT_COMMAND=
unset HISTFILE 2>/dev/null || true
set +o history 2>/dev/null || true
stty -echoctl 2>/dev/null || true
'''.strip()
        self.send_and_wait(bootstrap, timeout=10)

    def _read_until(self, end_marker: str, timeout: int = 60) -> str:
        assert self.chan is not None
        end_time = time.time() + timeout
        chunks: List[str] = []
        while time.time() < end_time:
            if self.chan.recv_ready():
                data = self.chan.recv(65535)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                chunks.append(text)
                if end_marker in "".join(chunks):
                    return "".join(chunks)
            else:
                time.sleep(0.1)
        raise TimeoutError(f"Timed out waiting for marker {end_marker!r}")

    def send_and_wait(self, command: str, timeout: int = 60) -> str:
        assert self.chan is not None
        marker = f"__LOCAL_DONE_{uuid.uuid4().hex}__"
        wrapped = f"{command}\nprintf '{marker}\\n'\n"
        self.chan.send(wrapped)
        return self._read_until(marker, timeout=timeout)

    def run_wrapped(self, command: str, timeout: int = 120) -> CommandResult:
        assert self.chan is not None
        token = uuid.uuid4().hex
        start = f"__CMD_START_{token}__"
        end = f"__CMD_END_{token}__"
        errfile = f"/tmp/{end}.stderr"
        sh = f'''
rm -f {shlex.quote(errfile)}
printf '{start}\\n'
({command}) 2>{shlex.quote(errfile)}
rc=$?
printf '{end} RC=%s\\n' "$rc"
if [ -s {shlex.quote(errfile)} ]; then
  printf '__STDERR_START_{token}__\\n'
  cat {shlex.quote(errfile)}
  printf '__STDERR_END_{token}__\\n'
fi
rm -f {shlex.quote(errfile)}
'''.strip()
        started_at = utc_now()
        raw = self.send_and_wait(sh, timeout=timeout)
        ended_at = utc_now()
        rc_match = re.search(rf"{re.escape(end)} RC=(\d+)", raw)
        rc = int(rc_match.group(1)) if rc_match else 999
        stderr_match = re.search(
            rf"__STDERR_START_{token}__\n(.*?)__STDERR_END_{token}__",
            raw,
            flags=re.S,
        )
        error = stderr_match.group(1).strip() if stderr_match else ""
        out_match = re.search(
            rf"{re.escape(start)}\n(.*?){re.escape(end)} RC=\d+",
            raw,
            flags=re.S,
        )
        output = out_match.group(1).strip() if out_match else raw.strip()
        return CommandResult(
            name=command,
            rc=rc,
            output=strip_shell_noise(output),
            error=strip_shell_noise(error),
            started_at=started_at,
            ended_at=ended_at,
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def strip_shell_noise(text: str) -> str:
    lines = text.replace("\r", "").split("\n")
    cleaned = []
    for line in lines:
        if line.strip() == "__JUMP_PROMPT__#":
            continue
        if line.strip().startswith("export PS1="):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def set_remote_env(session: JumpSession, name: str, value: str) -> None:
    session.send_and_wait(f"export {name}={shell_quote(value)}", timeout=10)


def ensure_known_host(session: JumpSession, host: str, port: int = 22, timeout: int = 20) -> None:
    cmd = (
        f"mkdir -p ~/.ssh && touch ~/.ssh/known_hosts && "
        f"ssh-keygen -F {shell_quote(host)} >/dev/null || "
        f"ssh-keyscan -p {port} -H {shell_quote(host)} >> ~/.ssh/known_hosts"
    )
    result = session.run_wrapped(cmd, timeout=timeout)
    if result.rc != 0:
        LOG.warning("ssh-keyscan failed for %s: %s", host, result.error or result.output)


def build_device_ssh_command(device: Dict, inner_command: str) -> str:
    host = device["host"]
    username = device["username"]
    port = int(device.get("port", 22))
    options = [
        f"-p {port}",
        "-o BatchMode=no",
        "-o PreferredAuthentications=password,keyboard-interactive,publickey",
        "-o PubkeyAuthentication=yes",
        "-o StrictHostKeyChecking=accept-new",
        "-o UserKnownHostsFile=$HOME/.ssh/known_hosts",
        "-o ConnectTimeout=15",
        "-o ServerAliveInterval=30",
        "-o ServerAliveCountMax=2",
    ]

    if device.get("use_sshpass", True):
        return (
            f"SSHPASS=\"$F5_SSH_PASS\" sshpass -e ssh {' '.join(options)} "
            f"{shell_quote(f'{username}@{host}')} {shell_quote(inner_command)}"
        )
    return f"ssh {' '.join(options)} {shell_quote(f'{username}@{host}')} {shell_quote(inner_command)}"


class TextFSMParser:
    def __init__(self, templates_dir: Path):
        self.templates_dir = templates_dir

    def parse(self, template_name: str, raw_text: str) -> pd.DataFrame:
        template_path = self.templates_dir / template_name
        with template_path.open("r", encoding="utf-8") as fh:
            fsm = textfsm.TextFSM(fh)
            rows = fsm.ParseText(raw_text)
        return pd.DataFrame(rows, columns=[h.lower() for h in fsm.header])


class DataSink:
    def __init__(self, db_url: Optional[str], out_dir: Path):
        self.db_url = db_url
        self.out_dir = out_dir
        self.engine = create_engine(db_url) if db_url else None
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def write_table(self, table: str, df: pd.DataFrame) -> None:
        csv_path = self.out_dir / f"{table}.csv"
        if csv_path.exists():
            existing = pd.read_csv(csv_path)
            df = pd.concat([existing, df], ignore_index=True)
        df.to_csv(csv_path, index=False)
        if self.engine is not None:
            df.to_sql(table, self.engine, if_exists="append", index=False)

    def write_raw(self, run_id: str, device_name: str, command_name: str, result: CommandResult) -> None:
        payload = {
            "run_id": run_id,
            "device_name": device_name,
            "command_name": command_name,
            "rc": result.rc,
            "started_at": result.started_at,
            "ended_at": result.ended_at,
            "stdout": result.output,
            "stderr": result.error,
        }
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{device_name}__{command_name}.json")
        raw_dir = self.out_dir / "raw" / run_id
        raw_dir.mkdir(parents=True, exist_ok=True)
        with (raw_dir / safe_name).open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)


class Collector:
    def __init__(self, session: JumpSession, parser: TextFSMParser, sink: DataSink, commands: List[Dict]):
        self.session = session
        self.parser = parser
        self.sink = sink
        self.commands = commands

    def collect_device(self, device: Dict, run_id: str) -> None:
        ensure_known_host(self.session, device["host"], int(device.get("port", 22)))
        for command in self.commands:
            cmd_name = command["name"]
            remote_command = build_device_ssh_command(device, command["command"])
            LOG.info("Running %s on %s", cmd_name, device["name"])
            result = self.session.run_wrapped(remote_command, timeout=int(device.get("timeout", 120)))
            self.sink.write_raw(run_id, device["name"], cmd_name, result)

            if result.rc != 0:
                LOG.error("Command %s failed on %s rc=%s stderr=%s", cmd_name, device["name"], result.rc, result.error)
                continue

            try:
                df = self.parser.parse(command["template"], result.output)
            except Exception as exc:
                LOG.exception("Parse failed for %s on %s: %s", cmd_name, device["name"], exc)
                continue

            if df.empty:
                LOG.warning("No rows parsed for %s on %s", cmd_name, device["name"])
                continue

            df.insert(0, "run_id", run_id)
            df.insert(1, "collected_at", result.ended_at)
            df.insert(2, "device_name", device["name"])
            df.insert(3, "device_host", device["host"])
            self.sink.write_table(command["table"], df)


def load_yaml(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def require_binary(session: JumpSession, binary: str) -> bool:
    result = session.run_wrapped(f"command -v {shell_quote(binary)} >/dev/null 2>&1", timeout=10)
    return result.rc == 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect F5 data through a jump host")
    ap.add_argument("--inventory", default="inventory.yaml")
    ap.add_argument("--commands", default=None, help="Optional YAML command catalog")
    ap.add_argument("--templates-dir", default="templates")
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--db-url", default=os.getenv("DB_URL"))
    ap.add_argument("--jump-password-env", default="JUMP_SSH_PASS")
    ap.add_argument("--f5-password-env", default="F5_SSH_PASS")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    configure_logging(args.verbose)

    inventory = load_yaml(Path(args.inventory))
    jump = inventory["jump_host"]
    devices = inventory["devices"]
    commands = load_yaml(Path(args.commands))["commands"] if args.commands else DEFAULT_COMMANDS

    jump_password = os.getenv(args.jump_password_env)
    if jump_password is None:
        jump_password = getpass.getpass(f"Jump host password for {jump['username']}@{jump['host']}: ")

    f5_password = os.getenv(args.f5_password_env)
    if f5_password is None:
        f5_password = getpass.getpass("F5 device SSH password: ")

    session = JumpSession(
        host=jump["host"],
        username=jump["username"],
        password=jump_password,
        port=int(jump.get("port", 22)),
        timeout=int(jump.get("timeout", 30)),
    )

    run_id = datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ")
    try:
        session.connect()
        if not require_binary(session, "ssh"):
            LOG.error("ssh not found on jump host")
            return 2
        if any(d.get("use_sshpass", True) for d in devices) and not require_binary(session, "sshpass"):
            LOG.error("sshpass not found on jump host but at least one device requires password SSH auth")
            return 2

        set_remote_env(session, "F5_SSH_PASS", f5_password)

        parser = TextFSMParser(Path(args.templates_dir))
        sink = DataSink(args.db_url, Path(args.out_dir))
        collector = Collector(session, parser, sink, commands)

        for device in devices:
            try:
                collector.collect_device(device, run_id)
            except (socket.timeout, TimeoutError) as exc:
                LOG.error("Timeout collecting %s: %s", device["name"], exc)
            except Exception as exc:
                LOG.exception("Unhandled error collecting %s: %s", device["name"], exc)
        LOG.info("Completed run %s", run_id)
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
