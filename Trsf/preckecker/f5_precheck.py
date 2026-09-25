#!/usr/bin/env python3
"""Read-only F5 migration validator (manifest schema 2).

`permissions`, `basic`, `platform`, `network`, `routes`, `system`, `applications`,
`references`, and `certificates` are implemented. BIG-IP
uses separate tmsh commands over one multiplexed SSH connection per endpoint;
F5OS uses one interactive appliance CLI session. Supply --snapshot-dir so unexpected CLI
output can be checked safely offline. Ctrl+C interrupts the current SSH
session and continues; Ctrl+\\ terminates the process. Permission probes use
short direct SSH calls; NTP synchronization uses the privileged BIG-IP login
when SSHPASSNET is set.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
STATUSES = ("PASS", "FAIL", "WARN", "ERROR", "SKIP", "INFO")
STATUS_COLORS = {"PASS": "\x1b[32m", "FAIL": "\x1b[31m", "WARN": "\x1b[33m",
                 "ERROR": "\x1b[35m", "SKIP": "\x1b[36m", "INFO": "\x1b[34m"}
SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
SAFE_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")
ERROR_TEXT = re.compile(r"(?im)^\s*(?:syntax error\b|%\s*(?:error|invalid|no entries)\b|error:|unknown command\b|permission denied\b)")
VERSION_TEXT = re.compile(r"\b(\d+(?:\.\d+){2,4})\s+([0-9]+(?:\.[0-9]+){2,4})\b")
F5OS_READY = re.compile(r"(?m)^\s*system\s+version\s+os-version\s+\S+")
BIGIP_READY = re.compile(r"(?im)^\s*Version\s+\d+(?:\.\d+){2,4}\s*$")
DISPLAY_PROMPT = re.compile(r"(?i)Display all\s+\d+\s+items\?")
DISPLAY_DECLINED = re.compile(r"(?i)Display all\s+\d+\s+items\?\s*\(y/n\)\s*n\b")
DISPLAY_ACCEPTED = re.compile(r"(?i)Display all\s+\d+\s+items\?\s*\(y/n\)\s*y\b")


def parse_checks(spec: str) -> set[str]:
    selected: set[str] = set()
    known = {"permissions", "basic", "platform", "network", "routes", "system", "applications",
             "references", "certificates"}
    for token in spec.split(","):
        token = token.strip().lower()
        if not token:
            raise ValueError("Empty --checks item")
        if token == "all":
            selected.update(known)
        elif token.startswith("!") and token[1:] in known:
            selected.discard(token[1:])
        elif token in known:
            selected.add(token)
        else:
            raise ValueError(f"Unsupported check category: {token!r}; available: {','.join(sorted(known))}")
    if not selected:
        raise ValueError("No checks selected")
    return selected


def parse_status_filter(spec: str | None) -> set[str] | None:
    if spec is None or spec.strip().lower() == "all":
        return None
    selected = {item.strip().upper() for item in spec.split(",")}
    if "" in selected or not selected <= set(STATUSES):
        raise ValueError("--filter accepts comma-separated PASS,FAIL,WARN,ERROR,SKIP,INFO or all")
    return selected


def checked_name(value: str, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"Invalid {label} in manifest: {value!r}")
    return value


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    if manifest.get("schema_version") != 2:
        raise ValueError("Expected manifest schema_version 2")
    devices = manifest.get("devices")
    if not isinstance(devices, dict) or set(devices) != {"a", "b"}:
        raise ValueError("Manifest must contain exactly devices.a and devices.b")
    for side in ("a", "b"):
        for role in ("source", "target", "rseries_host"):
            endpoint = devices[side][role]
            checked_name(endpoint["ssh_host"], SAFE_HOST, f"{side}.{role}.ssh_host")
        target = devices[side]["target"]
        for name in target["tenant_name_candidates"]:
            checked_name(name, SAFE_TENANT, f"{side}.target.tenant_name_candidate")
    return manifest


def clean_transcript(raw: str) -> str:
    return ANSI.sub("", raw.replace("\r\n", "\n").replace("\r", "\n")).replace("\x08", "")


def redact_transcript(raw: str) -> str:
    """Omit registration keys and key-file secrets from retained SSH snapshots."""
    raw = re.sub(r"(?im)^(\s*Registration key\s+)\S+", r"\g<1>[REDACTED]", raw)
    raw = re.sub(r"(?im)^(\s*passphrase\s+)(?:\"(?:\\.|[^\"\\])*\"|\S+)",
                 r"\g<1>[REDACTED]", raw)
    return re.sub(r"(?ms)^\s*-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                  "[REDACTED PRIVATE KEY]", raw)


def is_command_echo(line: str, command: str) -> bool:
    stripped = line.strip()
    if stripped == command:
        return True
    return bool(re.search(r"[#>]\s*" + re.escape(command) + r"\s*$", stripped, re.I))


def split_transcript(raw: str, commands: list[str]) -> dict[str, str]:
    """Separate echoed CLI commands without relying on vendor prompt syntax."""
    lines = clean_transcript(raw).splitlines()
    positions: list[int | None] = []
    search_from = 0
    for command in commands:
        pos = next((i for i in range(search_from, len(lines))
                    if is_command_echo(lines[i], command)), None)
        positions.append(pos)
        if pos is not None:
            search_from = pos + 1
    sections: dict[str, str] = {}
    for n, command in enumerate(commands):
        pos = positions[n]
        if pos is None:
            continue
        end = next((p for p in positions[n + 1:] if p is not None), len(lines))
        sections[command] = "\n".join(lines[pos + 1:end]).strip()
    # If a single remote command was accepted but the CLI did not echo it,
    # use the complete transcript. Multiple commands require boundaries.
    if len(commands) == 1 and commands[0] not in sections:
        sections[commands[0]] = clean_transcript(raw)
    return sections


def password_for(kind: str) -> tuple[str, str]:
    user = os.environ.get("USER")
    if not user:
        raise ValueError("Set USER to the regular F5 SSH username")
    env_name = "SSHPASSNET" if kind == "privileged" else "SSHPASS"
    login = f"{user}_net" if kind == "privileged" else user
    password = os.environ.get(env_name) or getpass.getpass(f"Enter password for {login}: ")
    if not password:
        raise ValueError(f"No password supplied for {login}")
    return login, password


def remote_probe_command(host: str, kind: str, command: str,
                         host_key_mode: str, timeout: int = 20) -> tuple[int, str]:
    """Run the same direct SSH command style used by f5_env_probe.py."""
    username = os.environ["USER"] + ("_net" if kind == "privileged" else "")
    env = os.environ.copy()
    env["SSHPASS"] = env["SSHPASSNET" if kind == "privileged" else "SSHPASS"]
    argv = ["sshpass", "-e", "ssh", "-o", "BatchMode=no",
            "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=8",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
            "-o", "LogLevel=ERROR"]
    if host_key_mode == "legacy":
        argv += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    else:
        argv += ["-o", f"StrictHostKeyChecking={host_key_mode}"]
    argv += ["-l", username, host, command]
    try:
        completed = subprocess.run(argv, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=timeout)
        return completed.returncode, redact_transcript(completed.stdout.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return 124, f"SSH probe timed out after {timeout}s"


def collect_privileged_ntp(host: str, host_key_mode: str) -> dict:
    rc, raw = remote_probe_command(host, "privileged", NTP_SYNC_COMMAND, host_key_mode)
    return {"host": host, "cli": "bigip", "account": "privileged",
            "commands": [NTP_SYNC_COMMAND], "returncode": rc,
            "error": None if rc == 0 else f"Privileged ntpq command exited {rc}; inspect snapshot",
            "raw": raw, "sections": {NTP_SYNC_COMMAND: raw}}


def check_permissions(reporter: Reporter, manifest: dict, host_key_mode: str,
                      *, offline: bool, check_system: bool, check_bigip: bool,
                      members: tuple[str, ...] = ("a", "b")) -> None:
    """Check the jump-host credentials and both BIG-IP roles before collection."""
    print("\nUser permissions")
    if offline:
        reporter.add("SKIP", "SSH permission probe", "Offline snapshot mode")
        return
    username = os.environ.get("USER")
    reporter.add("PASS" if username else "FAIL", "Regular username",
                 f"{username} (privileged: {username}_net)" if username else "USER is not set")
    for tool in ("ssh", "sshpass"):
        reporter.add("PASS" if shutil.which(tool) else "FAIL", f"Jump host {tool}",
                     "available" if shutil.which(tool) else "not found")
    regular = bool(os.environ.get("SSHPASS"))
    privileged = bool(os.environ.get("SSHPASSNET"))
    reporter.add("PASS" if regular else "WARN", "SSHPASS",
                 "set" if regular else "not set; regular collection will prompt and regular permission checks are skipped")
    reporter.add("PASS" if privileged else "WARN", "SSHPASSNET",
                 "set" if privileged else "not set; privileged permission checks"
                 + (" and NTP synchronization" if check_system else "") + " are skipped")
    if not check_bigip or not username or not shutil.which("ssh") or not shutil.which("sshpass"):
        return
    seen: set[str] = set()
    for side in members:
        for role in ("source", "target"):
            host = manifest["devices"][side][role]["ssh_host"]
            if host.casefold() in seen:
                continue
            seen.add(host.casefold())
            label = f"{side.upper()} {role} {host}"
            if regular:
                rc, output = remote_probe_command(host, "regular", "show sys version", host_key_mode)
                connected = rc == 0 and bool(BIGIP_READY.search(output))
                reporter.add("PASS" if connected else "FAIL", f"{label} regular SSH/tmsh",
                             "show sys version succeeded" if connected else f"Version probe failed (exit {rc})")
                if connected:
                    rc, output = remote_probe_command(host, "regular",
                                                      'bash -c "printf __F5_PERMISSION_BASH_OK__"', host_key_mode)
                    unrestricted = rc == 0 and "__F5_PERMISSION_BASH_OK__" in output
                    restricted = not unrestricted and rc not in (124, 255)
                    reporter.add("FAIL" if unrestricted else "PASS" if restricted else "WARN",
                                 f"{label} regular bash restriction",
                                 "regular user can enter bash" if unrestricted else
                                 "regular user cannot enter bash" if restricted else "bash restriction probe could not complete")
            if privileged:
                rc, output = remote_probe_command(host, "privileged", "show sys version", host_key_mode)
                connected = rc == 0 and bool(BIGIP_READY.search(output))
                reporter.add("PASS" if connected else "FAIL", f"{label} privileged SSH/tmsh",
                             "show sys version succeeded" if connected else f"Version probe failed (exit {rc})")
                if connected:
                    rc, output = remote_probe_command(host, "privileged",
                                                      'bash -c "printf __F5_PERMISSION_BASH_OK__"', host_key_mode)
                    allowed = rc == 0 and "__F5_PERMISSION_BASH_OK__" in output
                    reporter.add("PASS" if allowed else "WARN", f"{label} privileged bash access",
                                 "bash available" if allowed else "bash access not confirmed")


def collect_bigip_mux(host: str, commands: list[str], account: str,
                      timeout: int, ready_timeout: int, host_key_mode: str) -> dict:
    """One noninteractive tmsh command per SSH channel, sharing a TCP connection."""
    username, password = password_for(account)
    env = os.environ.copy()
    env["SSHPASS"] = password
    options = ["-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=10",
               "-o", "ServerAliveCountMax=2", "-o", "LogLevel=ERROR"]
    if host_key_mode == "legacy":
        options += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    else:
        options += ["-o", f"StrictHostKeyChecking={host_key_mode}"]
    sections: dict[str, str] = {}
    raw_parts: list[str] = []
    confirmed: dict[str, int] = {}
    command_errors: dict[str, str] = {}
    error = None
    returncode = 0
    with tempfile.TemporaryDirectory(prefix="f5-precheck-") as socket_dir:
        socket_path = str(Path(socket_dir) / "control")
        master_options = ["-o", "ControlMaster=yes", "-o", "ControlPersist=60",
                          "-o", f"ControlPath={socket_path}"]
        reuse_options = ["-o", "BatchMode=yes", "-S", socket_path]
        try:
            for index, command in enumerate(commands):
                print(f"  [{index + 1}/{len(commands)}] {command}", flush=True)
                argv = (["sshpass", "-e", "ssh"] if index == 0 else ["ssh"])
                argv += options + (master_options if index == 0 else reuse_options)
                argv += ["-l", username, host, command]
                try:
                    completed = subprocess.run(
                        argv, input=b"y\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env=env, timeout=min(ready_timeout, timeout) if index == 0 else timeout)
                except subprocess.TimeoutExpired as exc:
                    captured = (exc.stdout or b"").decode("utf-8", "replace")
                    raw_parts.append(f"$ {command}\n{redact_transcript(captured)}")
                    returncode = 124
                    error = f"{command} timed out after {min(ready_timeout, timeout) if index == 0 else timeout}s"
                    if re.search(r"(?i)\(less\s+\d+%\)|--More--|Display all\s+\d+\s+items\?", captured):
                        error += "; remote pager or display confirmation blocked output"
                    break
                output = redact_transcript(completed.stdout.decode("utf-8", "replace"))
                stderr = redact_transcript(completed.stderr.decode("utf-8", "replace"))
                raw_parts.append(f"$ {command}\n{output}" + (f"\n[ssh stderr] {stderr}" if stderr else ""))
                returncode = completed.returncode
                if returncode:
                    failure = f"{command} exited {returncode}: {(stderr or output).strip()[:180]}"
                    if command in HA_COMMANDS and index > 0:
                        command_errors[command] = failure
                        sections[command] = output
                        continue  # An HA probe must not hide other collected inventories.
                    error = failure
                    break
                if index == 0:
                    if not BIGIP_READY.search(clean_transcript(output)):
                        error = "BIG-IP readiness command returned no version; inspect raw snapshot"
                        break
                    if not Path(socket_path).exists():
                        error = "SSH control socket was not established; cannot reuse connection"
                        break
                if re.search(r"(?i)\(less\s+\d+%\)|--More--|\(END\)", output):
                    error = f"{command} stopped in a remote pager; inventory is incomplete"
                    break
                sections[command] = output
                accepted = len(DISPLAY_ACCEPTED.findall(output))
                if accepted:
                    confirmed[command] = accepted
        except KeyboardInterrupt:
            error = "SSH interrupted by Ctrl+C"
            returncode = 130
        finally:
            if Path(socket_path).exists():
                try:
                    subprocess.run(["ssh", *options, "-S", socket_path, "-O", "exit",
                                    "-l", username, host], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=5, env=env)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            env.pop("SSHPASS", None)
            password = ""
    return {"host": host, "cli": "bigip", "account": account,
            "commands": commands, "returncode": returncode, "error": error,
            "raw": "\n".join(raw_parts), "sections": sections, "command_errors": command_errors,
            "confirmed_display_prompts": confirmed}


def collect_ssh(host: str, cli: str, commands: list[str], account: str,
                timeout: int, ready_timeout: int, host_key_mode: str) -> dict:
    if not shutil.which("sshpass") or not shutil.which("ssh"):
        raise RuntimeError("ssh and sshpass are required on the jump host")
    if cli == "bigip":
        return collect_bigip_mux(host, commands, account, timeout, ready_timeout, host_key_mode)
    if cli != "f5os":
        raise ValueError(f"Unsupported CLI: {cli}")
    username, password = password_for(account)
    ssh_env = os.environ.copy()
    ssh_env["SSHPASS"] = password
    argv = ["sshpass", "-e", "ssh", "-tt", "-o", "BatchMode=no",
            "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2"]
    if host_key_mode == "legacy":
        # Identical to the working ksh collector; select explicitly if the
        # jump host does not have known host keys for these devices.
        argv += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    else:
        argv += ["-o", f"StrictHostKeyChecking={host_key_mode}"]
    argv += ["-l", username, host]
    # F5OS login lands in the appliance CLI; wait for the first probe result
    # before sending the remaining commands as in the working collector.
    collected = bytearray()
    error = None
    proc = None
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=ssh_env)
        assert proc.stdin and proc.stdout
        fd = proc.stdout.fileno()
        started = time.monotonic()
        deadline = started + timeout
        ready_deadline = started + min(ready_timeout, timeout)
        next_probe = started
        ready = False
        eof = False
        probe_announced = False
        try:
            while time.monotonic() < deadline:
                now = time.monotonic()
                if not ready and now >= next_probe and proc.poll() is None:
                    if not probe_announced:
                        print(f"  [1/{len(commands)}] {commands[0]}", flush=True)
                        probe_announced = True
                    try:
                        proc.stdin.write((commands[0] + "\n").encode())
                        proc.stdin.flush()
                    except BrokenPipeError:
                        break
                    next_probe = now + 3
                readable, _, _ = select.select([fd], [], [], min(0.5, max(0, deadline - now)))
                if readable:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        eof = True
                        break
                    collected.extend(chunk)
                    if not ready and F5OS_READY.search(clean_transcript(collected.decode("utf-8", "replace"))):
                        ready = True
                        try:
                            for index, command in enumerate(commands[1:], start=2):
                                print(f"  [queued {index}/{len(commands)}] {command}", flush=True)
                            proc.stdin.write(("\n".join([*commands[1:], "exit", ""])).encode())
                            proc.stdin.flush()
                            proc.stdin.close()
                        except BrokenPipeError:
                            break
                if not ready and time.monotonic() >= ready_deadline:
                    error = f"CLI readiness probe did not succeed within {ready_timeout}s"
                    break
            if not eof and proc.poll() is None:
                error = error or f"SSH timed out after {timeout}s"
                proc.kill()
            proc.wait(timeout=5)
        except KeyboardInterrupt:
            proc.kill()
            proc.wait(timeout=5)
            error = "SSH interrupted by Ctrl+C"
        collected.extend(proc.stdout.read() or b"")
        raw = redact_transcript(collected.decode("utf-8", "replace"))
        if not error and proc.returncode:
            diagnostic = next((line.strip() for line in reversed(clean_transcript(raw).splitlines())
                               if re.search(r"permission denied|host key|resolve hostname|connection refused|no route|timed out", line, re.I)), "")
            error = f"SSH exited {proc.returncode}" + (f": {diagnostic[:180]}" if diagnostic else "; inspect raw snapshot")
    finally:
        ssh_env.pop("SSHPASS", None)
        password = ""  # Never save credentials to the snapshot.
    return {"host": host, "cli": "f5os", "account": account, "commands": commands,
            "returncode": proc.returncode, "error": error, "raw": raw,
            "sections": split_transcript(raw, commands)}


def snapshot_path(directory: Path, side: str, role: str) -> Path:
    return directory / f"{side}_{role}.json"


def save_snapshot(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, temp_name = tempfile.mkstemp(prefix=".f5-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(record, file, indent=2)
            file.write("\n")
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def read_snapshot(path: Path, expected_host: str) -> dict:
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("host", "").lower() != expected_host.lower():
        raise ValueError(f"Snapshot host mismatch in {path}: expected {expected_host}")
    if not isinstance(record.get("sections"), dict):
        raise ValueError(f"Snapshot has no command sections: {path}")
    return record


def section(record: dict | None, command: str) -> tuple[str | None, str | None]:
    if record is None:
        return None, "No snapshot or SSH output"
    if record.get("error"):
        return None, record["error"]
    if command in record.get("command_errors", {}):
        return None, record["command_errors"][command]
    output = record.get("sections", {}).get(command)
    if output is None:
        return None, f"Command boundary missing: {command}; inspect raw snapshot"
    if ERROR_TEXT.search(output):
        return None, f"CLI rejected {command}; inspect raw snapshot"
    return output, None


def bigip_data(record: dict | None) -> dict:
    values: dict = {}
    raw = clean_transcript(record.get("raw", "")) if record else ""
    def find_value(pattern: str, output: str | None) -> re.Match[str] | None:
        # A command echo can be absent even when tmsh returned its value;
        # searching this endpoint's raw transcript recovers that field.
        return re.search(pattern, output or "") or (re.search(pattern, raw) if raw else None)

    def bigip_section(command: str) -> tuple[str | None, str | None]:
        output, error = section(record, command)
        if error and error.startswith("Command boundary missing:") and record and record.get("raw"):
            # Older snapshots were split by echoes, which tmsh sometimes
            # omits. Each snapshot contains only one BIG-IP endpoint.
            return clean_transcript(record["raw"]), None
        return output, error

    output, error = bigip_section("show sys version")
    if error:
        values["version_error"] = error
    else:
        version = find_value(r"(?im)^\s*Version\s+(\d+(?:\.\d+){2,4})\s*$", output)
        build = find_value(r"(?im)^\s*Build\s+([\d.]+)\s*$", output)
        values["version"] = version.group(1) if version else None
        values["build"] = build.group(1) if build else None
    output, error = bigip_section("list sys global-settings hostname")
    if error:
        values["hostname_error"] = error
    else:
        match = find_value(r"(?im)\bhostname[ \t]+([A-Za-z0-9][A-Za-z0-9._-]+)\b", output)
        values["hostname"] = match.group(1).strip('"') if match else None
    output, error = bigip_section("list sys management-ip")
    if error:
        values["management_ip_error"] = error
        values["management_prefix_length_error"] = error
    else:
        match = find_value(r"(?im)^\s*sys\s+management-ip\s+((?:\d{1,3}\.){3}\d{1,3})(?:/(\d+))?\b", output)
        values["management_ip"] = match.group(1) if match else None
        values["management_prefix_length"] = match.group(2) if match else None
    route_command = next((cmd for cmd in ("list sys management-route default", "list sys management-route")
                          if record and cmd in record.get("commands", [])), None)
    if not route_command:
        values["gateway_skipped"] = True  # Older snapshots did not collect this.
    else:
        output, error = bigip_section(route_command)
        if error:
            values["management_gateway_error"] = error
        else:
            match = find_value(r"(?is)\bsys[ \t]+management-route[ \t]+default[ \t]*\{[^}]*\bgateway[ \t]+((?:\d{1,3}\.){3}\d{1,3})\b", output)
            values["management_gateway"] = match.group(1) if match else None
    return values


NETWORK_COMMANDS = {"vlan": "list net vlan one-line", "self": "list net self one-line"}
ROUTE_COMMANDS = {"traffic": "list net route one-line",
                  "management": "list sys management-route one-line"}
SYSTEM_COMMANDS = {"dns": "list sys dns one-line", "ntp": "list sys ntp one-line"}
APPLICATION_COMMANDS = {"virtual": "list ltm virtual one-line",
                        "pool": "list ltm pool one-line"}
# Status field-fmt resolves version-dependent service aliases to numeric ports.
POOL_MEMBER_PORT_COMMAND = "show ltm pool members field-fmt"
REFERENCE_COMMANDS = {
    "http": "cd /Common; list ltm profile http one-line",
    "tcp": "cd /Common; list ltm profile tcp one-line",
    "fastl4": "cd /Common; list ltm profile fastl4 one-line",
    "one_connect": "cd /Common; list ltm profile one-connect one-line",
    "snatpool": "cd /Common; list ltm snatpool one-line",
    "rule": "cd /Common; list ltm rule",
    "policy": "cd /Common; list ltm policy one-line",
    "data_group": "cd /Common; list ltm data-group one-line",
    "cipher_group": "cd /Common; list ltm cipher group one-line",
    "cipher_rule": "cd /Common; list ltm cipher rule one-line",
}
CERTIFICATE_COMMANDS = {
    "client_ssl": "cd /Common; list ltm profile client-ssl",
    "server_ssl": "cd /Common; list ltm profile server-ssl",
    "virtual_profiles": "cd /Common; list ltm virtual profiles",
    "https_monitor": "cd /Common; list ltm monitor https",
    "cert": "cd /Common; list sys file ssl-cert all-properties",
    "key": "cd /Common; list sys file ssl-key all-properties",
    "bundle": "cd /Common; list sys file ssl-cert bundle-certificates",
}
# In `list ltm virtual one-line`, these switches stand alone without a value.
VIRTUAL_BARE_FLAGS = frozenset({"dhcp-relay", "ip-forward", "internal", "l2-forward",
                                "reject", "enabled", "disabled", "vlans-enabled",
                                "vlans-disabled"})
NTP_SYNC_COMMAND = 'bash -c "ntpq -np"'
HA_COMMANDS = ("show cm device", "show cm sync-status", "show cm failover-status",
               "list cm traffic-group", "show sys hardware")


def tmsh_objects(output: str, kind: str, *, allow_identical_duplicates: bool = False) -> dict[str, str]:
    """Extract complete tmsh objects, including multiline nested blocks."""
    objects: dict[str, str] = {}
    component = kind if " " in kind else "net " + kind
    header = re.compile(r"(?m)^\s*" + re.escape(component).replace(r"\ ", r"\s+")
                        + r"\s+(\S+)\s*\{")
    for match in header.finditer(output):
        start = match.end()
        end = closing_tmsh_brace(output, start)
        if end is None:
            raise ValueError(f"Incomplete {kind} object {match.group(1)!r}")
        name = match.group(1)
        if name in objects:
            if allow_identical_duplicates and tmsh_fields(objects[name]) == tmsh_fields(output[start:end]):
                continue  # A legacy snapshot may contain both the default query and the full listing.
            raise ValueError(f"Repeated {kind} object {name!r}")
        objects[name] = output[start:end]
    return objects


def closing_tmsh_brace(text: str, after_open: int) -> int | None:
    """Index of the matching closing brace, ignoring braces in quoted values."""
    depth = 1
    quoted = False
    escaped = False
    for index in range(after_open, len(text)):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char == "{":
            depth += 1
        elif not quoted and char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def echoed_inventory(record: dict, command: str) -> str | None:
    """Recover this command's output when the ordered transcript split missed its echo."""
    lines = clean_transcript(record.get("raw", "")).splitlines()
    positions = [i for i, line in enumerate(lines) if is_command_echo(line, command)]
    if not positions:
        return None
    start = positions[-1] + 1
    following = next((i for i in range(start, len(lines))
                      if any(is_command_echo(lines[i], other)
                             for other in record.get("commands", []) if other != command)), len(lines))
    return "\n".join(lines[start:following]).strip()


def inventory_pager_error(record: dict, command: str, output: str) -> str | None:
    if DISPLAY_DECLINED.search(output):
        return f"{command}: tmsh declined the display confirmation; inventory was not printed"
    count = len(DISPLAY_PROMPT.findall(output))
    confirmed = record.get("confirmed_display_prompts", {}).get(command, 0)
    if count > confirmed or re.search(r"(?i)--More--|\(END\)|\(less\s+\d+%\)", output):
        return f"{command} stopped at a tmsh display prompt; inventory may be incomplete"
    return None


def inventory_section(record: dict | None, command: str) -> tuple[str | None, str | None]:
    """Read an inventory, rejecting missing commands and truncated terminal output."""
    if record is None:
        return None, "No snapshot or SSH output"
    if record.get("error"):
        return None, record["error"]
    if command not in record.get("commands", []):
        return None, f"{command} absent from snapshot; collect a new snapshot for these checks"
    output, error = section(record, command)
    if error and not error.startswith("Command boundary missing:"):
        # tmsh can report an empty object inventory as 'No entries found'.
        if not (command in (*ROUTE_COMMANDS.values(), *APPLICATION_COMMANDS.values(),
                            POOL_MEMBER_PORT_COMMAND,
                            *REFERENCE_COMMANDS.values(), *CERTIFICATE_COMMANDS.values()) and
                re.search(r"(?i)no entries (?:found|to display)",
                          record.get("sections", {}).get(command, ""))):
            return None, error
        output, error = "", None
    if error:
        output = echoed_inventory(record, command)
        if output is None:
            # Older snapshots have interleaved command echoes such as "l ist".
            # Recover from object headers; each parser still validates its object.
            output = clean_transcript(record.get("raw", ""))
    if pager_error := inventory_pager_error(record, command, output or ""):
        return None, pager_error
    return output or "", None


def canonical_route_network(value: str) -> str:
    value = value.strip('"')
    if value in ("default", "default-inet6"):
        return "0.0.0.0/0" if value == "default" else "::/0"
    match = re.fullmatch(r"([^/%]+)(%\d+)?/(.+)", value)
    if not match:
        raise ValueError(f"Unrecognized route destination {value!r}")
    network = ipaddress.ip_network(f"{match.group(1)}/{match.group(3)}", strict=False)
    return f"{network.network_address}{match.group(2) or ''}/{network.prefixlen}"


def route_data(record: dict | None, kind: str) -> tuple[dict[str, dict] | None, str | None]:
    command = ROUTE_COMMANDS[kind]
    output, error = inventory_section(record, command)
    if error:
        return None, error
    try:
        component = "route" if kind == "traffic" else "sys management-route"
        if not output or not output.strip():
            recovered = echoed_inventory(record, command) if record else None
            if not recovered and record:
                recovered = clean_transcript(record.get("raw", ""))
            if recovered and re.search(r"(?m)^\s*" + (r"net\s+route" if kind == "traffic" else r"sys\s+management-route") + r"\s+\S+\s*\{", recovered):
                output = recovered
            elif not (record and re.search(r"(?i)no entries (?:found|to display)",
                                           record.get("sections", {}).get(command, ""))):
                return None, f"{command} returned no parseable output; cannot verify empty inventory"
        objects = tmsh_objects(output or "", component,
                               allow_identical_duplicates=kind == "management")
        if not objects and output.strip() and not re.search(r"(?i)no entries (?:found|to display)", output):
            return None, f"No {component} objects parsed; inspect raw snapshot"
        routes: dict[str, dict] = {}
        for name, body in objects.items():
            fields = tmsh_fields(body)
            name_part = name.rsplit("/", 1)[-1]
            partition = name.rsplit("/", 1)[0] if "/" in name else "/Common"
            destination = canonical_route_network(str(fields.get("network") or name_part))
            key = f"{partition}:{destination}"
            if key in routes:
                raise ValueError(f"Multiple {kind} routes to {key}: {routes[key]['name']} and {name}")
            keys = ("gw", "interface", "pool", "blackhole", "mtu") if kind == "traffic" else ("gateway", "type", "mtu")
            routes[key] = {"name": name, "settings": {field: fields[field] for field in keys if field in fields}}
        return routes, None
    except ValueError as exc:
        return None, str(exc)


def system_data(record: dict | None, kind: str) -> tuple[dict[str, object] | None, str | None]:
    command = SYSTEM_COMMANDS[kind]
    output, error = inventory_section(record, command)
    if error:
        return None, error
    try:
        header = re.search(r"(?m)^\s*sys\s+" + re.escape(kind) + r"\s*\{", output or "")
        if not header and record:
            raw = clean_transcript(record.get("raw", ""))
            header = re.search(r"(?m)^\s*sys\s+" + re.escape(kind) + r"\s*\{", raw)
            if header:
                output = raw
        if not header:
            return None, f"No sys {kind} object found; inspect raw snapshot"
        body = tmsh_block((output or "")[header.start():], kind)
        if body is None:
            raise ValueError(f"Incomplete sys {kind} object")
        lists = ("name-servers", "search") if kind == "dns" else ("servers",)
        result: dict[str, object] = {}
        for field in lists:
            contents = tmsh_block(body, field)
            if contents is None:
                if (value := tmsh_property(body, field)) not in (None, "none"):
                    raise ValueError(f"sys {kind}: unexpected {field} value {value!r}")
                result[field] = ()
            else:
                result[field] = tuple(token.strip('"') for token in
                                      re.findall(r'"(?:\\.|[^"\\])*"|[^\s{}]+', contents))
        if kind == "dns":
            result["number-of-dots"] = tmsh_property(body, "number-of-dots")
        else:
            result["timezone"] = tmsh_property(body, "timezone")
        return result, None
    except ValueError as exc:
        return None, str(exc)


def application_data(record: dict | None, kind: str) -> tuple[dict[str, dict] | None, str | None]:
    """Collect configured LTM objects; never mistake an unsplit command for an empty list."""
    command = APPLICATION_COMMANDS[kind]
    output, error = inventory_section(record, command)
    if error:
        return None, error
    status_pools: dict[str, str] = {}
    if kind == "pool":
        status_output, status_error = inventory_section(record, POOL_MEMBER_PORT_COMMAND)
        if status_error:
            return None, status_error
        try:
            for status_name, status_body in tmsh_objects(status_output or "", "ltm pool").items():
                path = object_path(status_name)
                if path in status_pools:
                    raise ValueError(f"Repeated pool status for {path}")
                status_pools[path] = status_body
        except ValueError as exc:
            return None, f"{POOL_MEMBER_PORT_COMMAND}: {exc}"
    try:
        objects = tmsh_objects(output or "", f"ltm {kind}")
        if not objects and record:
            raw = clean_transcript(record.get("raw", ""))
            if raw != output:
                objects = tmsh_objects(raw, f"ltm {kind}")
        if not objects:
            evidence = (record or {}).get("sections", {}).get(command, "")
            if not evidence:
                evidence = output or ""
            if re.search(r"(?i)no entries (?:found|to display)", evidence):
                return {}, None
            return None, f"{command} returned no parseable output; cannot verify empty inventory"
        parsed: dict[str, dict] = {}
        for name, body in objects.items():
            try:
                fields = tmsh_fields(body, bare_flags=VIRTUAL_BARE_FLAGS if kind == "virtual" else (),
                                     monitor_expressions=kind == "pool")
            except ValueError as exc:
                raise ValueError(f"ltm {kind} {name}: {exc}") from exc
            entry: dict = {"fields": fields}
            if kind == "virtual":
                entry["destination"] = fields.get("destination")
                entry["protocol"] = fields.get("ip-protocol", "tcp")
                if not entry["destination"]:
                    raise ValueError(f"ltm virtual {name}: destination missing")
            else:
                member_block = tmsh_block(body, "members")
                members: dict[str, dict] = {}
                status_body = status_pools.get(object_path(name))
                status_block = tmsh_block(status_body, "members") if status_body is not None else None
                status_members: dict[str, str] = {}
                for status_member_name, status_member_body in tmsh_objects_from_block(status_block or ""):
                    status_key = scoped_name(status_member_name, name)
                    if status_key in status_members:
                        raise ValueError(f"ltm pool {name}: ambiguous member status {status_key}")
                    status_members[status_key] = status_member_body
                for member, member_body in tmsh_objects_from_block(member_block or ""):
                    properties = tmsh_fields(member_body, monitor_expressions=True)
                    status_key = scoped_name(member, name)
                    if status_key not in status_members:
                        raise ValueError(f"ltm pool {name}: member {member} missing from field-fmt status")
                    status_member = status_members.pop(status_key)
                    port = tmsh_property(status_member, "port")
                    if port is None or not port.isdigit() or not 0 <= int(port) <= 65535:
                        raise ValueError(f"ltm pool {name}: member {member} has no valid numeric status port")
                    address = properties.get("address") or tmsh_property(status_member, "addr")
                    if not address:
                        raise ValueError(f"ltm pool {name}: member {member} has no resolved address")
                    status_address = tmsh_property(status_member, "addr")
                    if status_address and status_address != address:
                        raise ValueError(f"ltm pool {name}: member {member} status address differs from configuration")
                    # Compare the actual endpoint even when a service alias changes.
                    identity = f"{address}:{port}"
                    if identity in members:
                        raise ValueError(f"ltm pool {name}: repeated member endpoint {identity}")
                    members[identity] = {"name": member, "fields": properties}
                if member_block is None and fields.get("members") not in (None, "none"):
                    raise ValueError(f"ltm pool {name}: unrecognized members value")
                if status_members:
                    raise ValueError(f"ltm pool {name}: status has unrecognized members {sorted(status_members)}")
                entry["members"] = members
            parsed[name] = entry
        return parsed, None
    except ValueError as exc:
        return None, str(exc)


def tmsh_block(body: str, property_name: str) -> str | None:
    match = re.search(r"\b" + re.escape(property_name) + r"\s*\{", body)
    if not match:
        return None
    start = match.end()
    end = closing_tmsh_brace(body, start)
    if end is None:
        raise ValueError(f"Incomplete {property_name} block")
    return body[start:end]


def tmsh_property(body: str, name: str) -> str | None:
    match = re.search(r"(?<![\w-])" + re.escape(name) +
                      r'\s+(?!\{)("(?:\\.|[^"\\])*"|[^\s{}]+)', body)
    return match.group(1).strip('"') if match else None


def tmsh_fields(body: str, *, bare_flags: frozenset[str] | tuple = (),
                monitor_expressions: bool = False) -> dict[str, str | tuple[str, ...]]:
    """Read every top-level property, preserving nested properties as tokens."""
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[{}]|[^\s{}"]+', body)
    fields: dict[str, str | tuple[str, ...]] = {}
    index = 0
    while index < len(tokens):
        key = tokens[index]
        if key in ("{", "}"):
            raise ValueError(f"Malformed tmsh property near {key!r}")
        index += 1
        if key in bare_flags:
            fields[key] = "present"
            continue
        if index >= len(tokens):
            raise ValueError(f"Malformed tmsh property near {key!r}")
        if monitor_expressions and key == "monitor":
            expression: list[str] = []
            if tokens[index:index + 1] == ["min"]:
                if (index + 4 >= len(tokens) or not tokens[index + 1].isdigit() or
                        tokens[index + 2:index + 4] != ["of", "{"]):
                    raise ValueError("Malformed pool monitor min N of expression")
                start = index
                index += 4
                depth = 1
                while index < len(tokens) and depth:
                    depth += (tokens[index] == "{") - (tokens[index] == "}")
                    index += 1
                if depth:
                    raise ValueError("Incomplete pool monitor expression")
                expression.extend(tokens[start:index])
            else:
                expression.append(tokens[index])
                index += 1
            while index < len(tokens) and tokens[index] in ("and", "or"):
                if index + 1 >= len(tokens):
                    raise ValueError("Incomplete pool monitor conjunction")
                expression.extend(tokens[index:index + 2])
                index += 2
            fields[key] = " ".join(expression)
            continue
        if tokens[index] == "{":
            index += 1
            depth = 1
            contents: list[str] = []
            while index < len(tokens) and depth:
                token = tokens[index]
                depth += (token == "{") - (token == "}")
                if depth:
                    contents.append(token)
                index += 1
            if depth:
                raise ValueError(f"Incomplete tmsh property {key!r}")
            # Service order does not affect the port-lockdown policy.
            fields[key] = tuple(sorted(contents)) if key == "allow-service" else tuple(contents)
        else:
            fields[key] = tokens[index].strip('"')
            index += 1
    return fields


def scoped_name(name: str, owner: str = "/Common/example") -> str:
    """Resolve a tmsh reference in the referencing object's partition."""
    return name if name.startswith("/") else object_path(owner).rsplit("/", 1)[0] + "/" + name


def object_inventory(record: dict | None, command: str, kind: str) -> tuple[dict[str, str] | None, str | None]:
    output, error = inventory_section(record, command)
    if error:
        return None, error
    try:
        objects = tmsh_objects(output or "", kind)
        if objects:
            return {object_path(name): body for name, body in objects.items()}, None
        if re.search(r"(?i)no entries (?:found|to display)", output or ""):
            return {}, None
        return None, f"{command}: no parseable objects; cannot verify an empty inventory"
    except ValueError as exc:
        return None, str(exc)


def rule_inventory(record: dict | None) -> tuple[dict[str, str] | None, str | None]:
    """tmsh prints Tcl iRules multiline; do not count braces in quoted Tcl or comments."""
    command = REFERENCE_COMMANDS["rule"]
    output, error = inventory_section(record, command)
    if error:
        return None, error
    headers = list(re.finditer(r"(?m)^ltm\s+rule\s+(\S+)\s+\{[ \t]*$", output or ""))
    if not headers:
        if re.search(r"(?i)no entries (?:found|to display)", output or ""):
            return {}, None
        return None, f"{command}: no rule headers; cannot verify empty inventory"
    rules: dict[str, str] = {}
    for index, header in enumerate(headers):
        stop = headers[index + 1].start() if index + 1 < len(headers) else len(output or "")
        segment = (output or "")[header.end():stop]
        # The last column-zero closing brace before the next tmsh object ends
        # this rule; Tcl's own closing braces may also be in column zero.
        closings = list(re.finditer(r"(?m)^\}[ \t]*(?:\n|$)", segment))
        if not closings:
            return None, f"ltm rule {header.group(1)}: closing brace missing"
        closing = closings[-1]
        if index + 1 < len(headers) and segment[closing.end():].strip():
            return None, f"ltm rule {header.group(1)}: unexpected text after closing brace"
        name = object_path(header.group(1))
        if name in rules:
            return None, f"ltm rule {name}: duplicate object"
        body = segment[:closing.start()].replace("\r\n", "\n").strip("\n")
        body = re.sub(r"(?m)^\s*(?:last-modified|verification-status)\s+[^\n]*\n?", "", body)
        rules[name] = body
    return rules, None


def rule_digest(body: str) -> str:
    return hashlib.md5(body.encode("utf-8")).hexdigest()


def tcl_command_words(text: str) -> list[str]:
    """Split Tcl words while preserving bracketed values with embedded spaces."""
    words: list[str] = []
    current: list[str] = []
    brackets = braces = 0
    quoted = escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            quoted = not quoted
            current.append(char)
        elif not quoted and char == "[":
            brackets += 1
            current.append(char)
        elif not quoted and char == "]" and brackets:
            brackets -= 1
            current.append(char)
        elif not quoted and char == "{":
            braces += 1
            current.append(char)
        elif not quoted and char == "}" and braces:
            braces -= 1
            current.append(char)
        elif not quoted and not brackets and not braces and char in ";\n":
            if current:
                words.append("".join(current))
            break
        elif not quoted and not brackets and not braces and char.isspace():
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(char)
    else:
        if current:
            words.append("".join(current))
    return words


def data_group_inventory(record: dict | None) -> tuple[dict[str, dict] | None, str | None]:
    command = REFERENCE_COMMANDS["data_group"]
    output, error = inventory_section(record, command)
    if error:
        return None, error
    try:
        groups: dict[str, dict] = {}
        for subtype in ("internal", "external"):
            for name, body in tmsh_objects(output or "", f"ltm data-group {subtype}").items():
                key = object_path(name)
                if key in groups:
                    raise ValueError(f"Repeated data-group {key}")
                fields = tmsh_fields(body)
                if subtype == "internal" and (records := tmsh_block(body, "records")) is not None:
                    entries = {record_name: tmsh_fields(record_body)
                               for record_name, record_body in tmsh_objects_from_block(records)}
                    fields["records"] = tuple(sorted((name, tuple(sorted(row.items())))
                                                     for name, row in entries.items()))
                groups[key] = {"subtype": subtype, "fields": fields}
        if groups:
            return groups, None
        if re.search(r"(?i)no entries (?:found|to display)", output or ""):
            return {}, None
        return None, f"{command}: no parseable data groups"
    except ValueError as exc:
        return None, str(exc)


def rule_dependencies(body: str) -> tuple[set[str], set[str], set[str]]:
    """Extract literal cross-rule calls and common class/legacy data-group uses."""
    rules: set[str] = set()
    groups: set[str] = set()
    unresolved: set[str] = set()
    # A comment at the beginning of a Tcl line is not executable.
    code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
    for match in re.finditer(r"\bcall\s+([^\s;{}\[\]]+)", code):
        ref = match.group(1).strip('"')
        if "$" in ref or "[" in ref:
            unresolved.add(f"dynamic iRule call {ref}")
        elif "::" in ref:
            rules.add(ref.rsplit("::", 1)[0])
        else:
            unresolved.add(f"unrecognized iRule call {ref}")
    def add_group(raw: str, operation: str) -> None:
        # The closing ] belongs to the enclosing Tcl command, not the name.
        if raw.lstrip().startswith("[") or "$" in raw:
            unresolved.add(f"dynamic data-group in {operation}")
            return
        ref = raw.strip(' \t\r\n\"\'{}[]();,')
        if re.fullmatch(r"(?:/[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+", ref):
            groups.add(ref)
        else:
            unresolved.add(f"unparsed data-group in {operation}: {raw[:80]}")

    for match in re.finditer(r"\bclass\s+(match|lookup|names|exists|size|element)\s+", code):
        operation = match.group(1)
        tokens = tcl_command_words(code[match.end():])
        if operation == "match":
            # Tcl's -- ends the option list; it is not the match operator.
            if tokens and tokens[0] == "-value":
                tokens = tokens[1:]
            if tokens and tokens[0] == "--":
                tokens = tokens[1:]
        position = 2 if operation == "match" else 1 if operation == "lookup" else 0
        if len(tokens) <= position:
            unresolved.add(f"unparsed class {operation}")
        elif operation == "match" and tokens[1] not in {
                "equals", "starts_with", "ends_with", "contains", "matches_regex", "eq", "ne"}:
            unresolved.add(f"unparsed class match operator {tokens[1][:40]}")
        else:
            add_group(tokens[position], f"class {operation}")
    for match in re.finditer(r"\b(matchclass|findclass)\s+", code):
        operation = match.group(1)
        tokens = tcl_command_words(code[match.end():])
        position = 2 if operation == "matchclass" else 1
        if len(tokens) <= position:
            unresolved.add(f"unparsed {operation} data-group")
        else:
            add_group(tokens[position], operation)
    return rules, groups, unresolved


def normalize_self_address(address: str) -> str:
    """Normalize masks while keeping BIG-IP route-domain suffixes such as %1."""
    match = re.fullmatch(r"([^/%]+)(%\d+)?/(.+)", address)
    if not match:
        raise ValueError(f"Invalid self IP address: {address!r}")
    interface = ipaddress.ip_interface(f"{match.group(1)}/{match.group(3)}")
    return f"{interface.ip}{match.group(2) or ''}/{interface.network.prefixlen}"


def network_data(record: dict | None, kind: str) -> tuple[dict[str, dict] | None, str | None]:
    """Read a selected command; missing echoes may fall back to this host's raw output."""
    command = NETWORK_COMMANDS[kind]
    if record is None:
        return None, "No snapshot or SSH output"
    if record.get("error"):
        return None, record["error"]
    if command not in record.get("commands", []):
        return None, f"{command} absent from snapshot; collect a new network snapshot"
    output, error = section(record, command)
    raw = clean_transcript(record.get("raw", ""))
    if error and not error.startswith("Command boundary missing:"):
        return None, error
    if error:
        output = raw
    if pager_error := inventory_pager_error(record, command, output or ""):
        return None, pager_error
    try:
        objects = tmsh_objects(output or "", kind)
        if not objects and raw and raw != output:
            objects = tmsh_objects(raw, kind)
        if not objects:
            return None, f"No net {kind} objects found; inspect raw snapshot for pager or CLI errors"
        result: dict[str, dict] = {}
        for name, body in objects.items():
            fields = tmsh_fields(body)
            if kind == "vlan":
                interfaces = tmsh_block(body, "interfaces")
                members = []
                if interfaces is not None:
                    for member, props in tmsh_objects_from_block(interfaces):
                        tagged = "untagged" if re.search(r"\buntagged\b", props) else (
                            "tagged" if re.search(r"\btagged\b", props) else "unspecified")
                        members.append((member, tagged))
                tag = tmsh_property(body, "tag")
                if tag is None:
                    raise ValueError(f"net vlan {name}: tag missing")
                result[name] = {"tag": tag, "interfaces": sorted(members),
                                "failsafe": {key: value for key, value in fields.items()
                                             if key == "failsafe" or key.startswith("failsafe-")}}
            else:
                address = tmsh_property(body, "address")
                vlan = tmsh_property(body, "vlan")
                group = tmsh_property(body, "traffic-group")
                if not all((address, vlan, group)):
                    raise ValueError(f"net self {name}: address, vlan or traffic-group missing")
                try:
                    address = normalize_self_address(address)
                except ValueError as exc:
                    raise ValueError(f"net self {name}: invalid address {address!r}") from exc
                fields["address"] = address
                result[name] = {"address": address, "vlan": vlan,
                                "properties": fields}
        return result, None
    except ValueError as exc:
        return None, str(exc)


def tmsh_objects_from_block(block: str) -> list[tuple[str, str]]:
    """Read nested objects, including unquoted cert-key-chain slot names with spaces."""
    members: list[tuple[str, str]] = []
    index = 0
    while index < len(block):
        while index < len(block) and block[index].isspace():
            index += 1
        if index == len(block):
            break
        opening = block.find("{", index)
        if opening < 0:
            raise ValueError(f"Expected a named nested block after {block[index:].strip()!r}")
        name = block[index:opening].strip().strip('"')
        if not name or "}" in name:
            raise ValueError(f"Invalid nested object name {name!r}")
        closing = closing_tmsh_brace(block, opening + 1)
        if closing is None:
            raise ValueError(f"Incomplete nested block {name!r}")
        members.append((name, block[opening + 1:closing]))
        index = closing + 1
    return members


def parse_f5os_tenant(output: str) -> dict | None:
    if ERROR_TEXT.search(output):
        return None
    name = re.search(r"(?im)^\s*tenants\s+tenant\s+([A-Za-z0-9-]+)\s*$", output)
    if not name:
        return None
    state: dict[str, str] = {"name": name.group(1)}
    for key, value in re.findall(r"(?im)^\s*state\s+([\w-]+)\s+(.+?)\s*$", output):
        state[key.lower()] = value.strip().strip('"')
    mac = re.search(r"(?im)^\s*(?:state\s+)?mac-data\s+base-mac\s+([0-9a-f:.-]+)\s*$", output)
    if mac:
        state["base_mac"] = mac.group(1)
    # `state image` is the deployment image. Only image-version reflects the
    # version currently running inside the tenant.
    running = VERSION_TEXT.search(state.get("image-version", ""))
    state["running_version"] = running.group(1) if running else None
    state["running_build"] = running.group(2) if running else None
    return state


def f5os_tenants(output: str) -> list[dict]:
    """`show tenants | nomore` returns every tenant in one command."""
    markers = list(re.finditer(r"(?im)^\s*tenants\s+tenant\s+[A-Za-z0-9-]+\s*$", output))
    return [tenant for i, marker in enumerate(markers)
            if (tenant := parse_f5os_tenant(output[marker.start():
                                             markers[i + 1].start() if i + 1 < len(markers) else len(output)]))]


def f5os_fips(output: str) -> dict:
    """Read partition capacity from the F5OS `show fips` table."""
    partitions = {}
    for line in output.splitlines():
        fields = line.split()
        if (len(fields) >= 8 and fields[1].isdigit() and fields[2].isdigit()
                and fields[3] in ("enabled", "disabled") and fields[4].lstrip("-").isdigit()
                and fields[5].isdigit() and fields[6].isdigit()
                and re.fullmatch(r"[A-Fa-f0-9]+(?::[A-Fa-f0-9]+)+\.[A-Fa-f0-9]+", fields[7])):
            partitions[fields[0].casefold()] = {"name": fields[0], "keys": fields[1],
                                                 "accelerator_devices": fields[2],
                                                 "state": fields[4]}
    return partitions


def licensed_host_model(output: str) -> str | None:
    """Read the hardware model on the Active Modules Local Traffic Manager line."""
    active = re.search(r"(?im)^\s*Active Modules\s*$", output)
    if not active:
        return None
    modules = output[active.end():]
    models = set(re.findall(
        r"(?im)^\s*Local Traffic Manager,\s*(r\d+(?:-[A-Za-z0-9]+)*)\s*(?=\(|$)",
        modules))
    return next(iter(models)) if len(models) == 1 else None


def f5os_data(record: dict | None, candidates: list[str]) -> dict:
    values: dict = {}
    output, error = section(record, "show system licensing | nomore")
    if error:
        values["model_error"] = error
    else:
        values["model"] = licensed_host_model(output)
        if values["model"] is None:
            values["model_error"] = "Model missing or ambiguous in Active Modules / Local Traffic Manager license entry"
    output, error = section(record, "show system state hostname")
    if error:
        values["hostname_error"] = error
    else:
        match = re.search(r"(?im)^\s*(?:system\s+)?(?:state\s+)?hostname\s+(\S+)", output)
        values["hostname"] = match.group(1).strip('"') if match else None
    output, error = section(record, "show system mgmt-ip")
    if error:
        values["management_ip_error"] = error
    else:
        match = re.search(r"(?im)^\s*system\s+mgmt-ip\s+state\s+ipv4\s+system\s+address\s+((?:\d{1,3}\.){3}\d{1,3})\b", output)
        values["management_ip"] = match.group(1) if match else None
    output, error = section(record, "show tenants | nomore")
    if error:
        values["tenant_error"] = error
    else:
        by_name = {item["name"].casefold(): item for item in f5os_tenants(output)}
        for name in dict.fromkeys(candidates):
            if name.casefold() in by_name:
                values["tenant"] = by_name[name.casefold()]
                values["matched_lookup"] = name
                break
    if "tenant" not in values:
        values["tenant_error"] = values.get("tenant_error") or "Tenant not found with either name case in show tenants output"
    output, error = section(record, "show fips | nomore")
    if error:
        values["fips_error"] = error
    else:
        values["fips_partitions"] = f5os_fips(output)
    return values


class Reporter:
    def __init__(self, status_filter: set[str] | None = None, color: bool = False) -> None:
        self.results: list[tuple[str, str, str]] = []
        self.status_filter = status_filter
        self.color = color
        self.displayed = 0

    def add(self, status: str, label: str, detail: str, *, force: bool = False,
            inline: bool = False) -> None:
        self.results.append((status, label, detail))
        if force or self.status_filter is None or status in self.status_filter:
            token = f"[{status:<5}]"
            if self.color:
                token = f"{STATUS_COLORS[status]}{token}\x1b[0m"
            print(f"{token} {detail}" if inline else f"{token} {label:<45} {detail}")
            self.displayed += 1

    def red(self, value: object) -> str:
        rendered = str(value)
        return f"\x1b[31m{rendered}\x1b[0m" if self.color else rendered

    def compare_items(self, label: str, source: object, target: object,
                      *, status: str = "FAIL", ordered: bool = False) -> None:
        """Show item deltas without hiding a difference in order-sensitive lists."""
        before = list(source) if isinstance(source, (tuple, list, set)) else [source]
        after = list(target) if isinstance(target, (tuple, list, set)) else [target]
        before, after = [repr(item) for item in before], [repr(item) for item in after]
        if before == after or (not ordered and Counter(before) == Counter(after)):
            self.add("PASS", label, f"{len(before)} items match")
            return
        missing, extra = Counter(before) - Counter(after), Counter(after) - Counter(before)
        def display(items: Counter) -> str:
            return ", ".join(f"{item} (x{count})" if count > 1 else item
                             for item, count in sorted(items.items()))
        pieces = []
        if missing:
            pieces.append("missing on target: " + self.red(display(missing)))
        if extra:
            pieces.append("extra on target: " + self.red(display(extra)))
        if ordered and not pieces:
            pieces.append("order differs: source=" + self.red(before) + " target=" + self.red(after))
        self.add(status, label, "; ".join(pieces))

    def compare(self, label: str, expected: object, actual: object,
                error: str | None = None, *, casefold: bool = False,
                hostname_suffix: str | None = None) -> None:
        if error:
            self.add("ERROR", label, error)
        elif actual is None or str(actual).strip() == "":
            self.add("ERROR", label, "Value missing in device output")
        elif expected is None:
            self.add("SKIP", label, "No expected value in manifest")
        else:
            a, b = str(actual).strip(), str(expected).strip()
            if hostname_suffix and not b.casefold().endswith(hostname_suffix.casefold()):
                b += hostname_suffix
            matches = a.casefold() == b.casefold() if casefold else a == b
            self.add("PASS" if matches else "FAIL", label,
                     f"expected={b!r} actual={a!r}")

    def finish(self) -> int:
        counts = {status: sum(1 for row in self.results if row[0] == status)
                  for status in STATUSES}
        summary = " ".join(f"{key}={value}" for key, value in counts.items())
        if self.status_filter is not None:
            summary += f" | displayed={self.displayed} filter={','.join(sorted(self.status_filter))}"
        print("\n" + summary)
        return 2 if counts["ERROR"] else 1 if counts["FAIL"] else 0


def compare_bigip(reporter: Reporter, side: str, role: str, expected: dict,
                  observed: dict, hostname_suffix: str) -> None:
    prefix = f"{side.upper()} {role} BIG-IP"
    reporter.compare(f"{prefix} hostname", expected["expected_hostname"],
                     observed.get("hostname"), observed.get("hostname_error"),
                     casefold=True, hostname_suffix=hostname_suffix)
    reporter.compare(f"{prefix} management IP", expected["management_ip"],
                     observed.get("management_ip"), observed.get("management_ip_error"))
    if role == "source":
        if observed.get("version_error") or not observed.get("version") or not observed.get("build"):
            reporter.add("ERROR", f"{prefix} software", observed.get("version_error") or "Version or build missing")
        else:
            version = observed["version"]
            reporter.add("INFO", f"{prefix} software", f"version={version} build={observed.get('build')} major={version.split('.')[0]}")
    else:
        expected_software = expected["software"]
        reporter.compare(f"{prefix} version", expected_software["version"],
                         observed.get("version"), observed.get("version_error"))
        reporter.compare(f"{prefix} build", expected_software["build"],
                         observed.get("build"), observed.get("version_error"))
        reporter.compare(f"{prefix} management prefix", expected["management_prefix_length"],
                         observed.get("management_prefix_length"), observed.get("management_prefix_length_error"))
        if observed.get("gateway_skipped"):
            reporter.add("SKIP", f"{prefix} management gateway", "Command absent from older snapshot")
        else:
            reporter.compare(f"{prefix} management gateway", expected["management_gateway"],
                             observed.get("management_gateway"), observed.get("management_gateway_error"))


def parse_device_ha(output: str) -> dict[str, str]:
    parts = re.split(r"(?im)^\s*CentMgmt::Device:\s*(\S+)", output)
    states: dict[str, str] = {}
    for index in range(1, len(parts), 2):
        name, body = parts[index:index + 2]
        hostname = re.search(r"(?im)^\s*Hostname\s+(\S+)", body)
        state = re.search(r"(?im)^\s*Device HA State\s+(\S+)", body)
        if state:
            states[(hostname.group(1) if hostname else name).casefold()] = state.group(1).casefold()
    return states


def derive_masquerade_mac(value: str) -> str:
    if not re.fullmatch(r"[\da-fA-F]{2}(?::[\da-fA-F]{2}){5}", value):
        raise ValueError("Invalid base MAC address")
    octets = value.lower().split(":")
    first = int(octets[0], 16)
    if first & 1:
        raise ValueError("Base MAC is multicast; cannot derive a unicast masquerade MAC")
    octets[0] = f"{first | 2:02x}"
    return ":".join(octets)


def hardware_base_mac(output: str) -> str:
    """Read the base MAC from an unfiltered `show sys hardware` transcript."""
    candidates = {item.casefold() for item in re.findall(
        r"(?im)^[ \t]*Base MAC[ \t]*:?[ \t]+([\da-fA-F]{2}(?::[\da-fA-F]{2}){5})\b", output)}
    if len(candidates) != 1:
        raise ValueError("Base MAC missing from hardware output" if not candidates else
                         "Multiple different base MACs in hardware output")
    return next(iter(candidates))


def compare_target_ha(reporter: Reporter, manifest: dict, collected: dict[str, dict | None],
                      hostname_suffix: str, members: tuple[str, ...]) -> None:
    """Check the target pair, including evidence from a single selected member."""
    expected_hosts = {}
    for side in ("a", "b"):
        host = manifest["devices"][side]["target"]["expected_hostname"]
        if not host.casefold().endswith(hostname_suffix.casefold()):
            host += hostname_suffix
        expected_hosts[side] = host.casefold()
    observed_macs: dict[str, str] = {}
    base_candidates: dict[str, str] = {}
    for side in members:
        record = collected.get(side)
        prefix = f"{side.upper()} target"
        output, error = section(record, "show cm device")
        if error:
            reporter.add("ERROR", f"{prefix} HA device states", error)
        else:
            states = parse_device_ha(output)
            if not states:
                reporter.add("ERROR", f"{prefix} HA device states", "No device HA states parsed")
            else:
                for device_side, wanted in (("a", "standby"), ("b", "active")):
                    actual = states.get(expected_hosts[device_side])
                    reporter.add("ERROR" if actual is None else "PASS" if actual == wanted else "FAIL",
                                 f"{prefix} member {device_side.upper()} HA state",
                                 f"expected={wanted} actual={actual or 'not found'}")
        output, error = section(record, "show cm sync-status")
        if error:
            reporter.add("ERROR", f"{prefix} sync", error)
        else:
            match = re.search(r"(?im)^\s*status\s+(.+?)\s*$", output)
            groups = re.findall(r"(?im)^\s*\S+\s+\(([^)]+)\):", output)
            actual = match.group(1).strip() if match else None
            if actual is None:
                reporter.add("ERROR", f"{prefix} sync", "Sync status missing from output")
            else:
                healthy = actual.casefold() == "in sync" and all(g.casefold() == "in sync" for g in groups)
                reporter.add("PASS" if healthy else "FAIL", f"{prefix} sync",
                             f"status={actual}; device groups={groups or '(not listed)'}")
        output, error = section(record, "show cm failover-status")
        if error:
            reporter.add("ERROR", f"{prefix} failover", error)
        else:
            match = re.search(r"(?im)^\s*status\s+(ACTIVE|STANDBY|OFFLINE|UNKNOWN)\s*$", output)
            expected = "STANDBY" if side == "a" else "ACTIVE"
            actual = match.group(1).upper() if match else None
            reporter.add("ERROR" if actual is None else "PASS" if actual == expected else "FAIL",
                         f"{prefix} failover role", f"expected={expected} actual={actual or 'missing'}")
            connections = output.split("CM::Failover Connections", 1)
            statuses = re.findall(
                r"(?im)^\s*(?:(?:\d{1,3}\.){3}\d{1,3}:\d+|eth\S+\s+\S+:\d+)\s+.+?\s+(ok|error)\s*$",
                connections[1] if len(connections) == 2 else "")
            good = sum(item.casefold() == "ok" for item in statuses)
            failed = sum(item.casefold() != "ok" for item in statuses)
            reporter.add("ERROR" if not statuses else "FAIL" if not good else "WARN" if failed else "PASS",
                         f"{prefix} failover links",
                         f"working={good} failed={failed}" if statuses else "No failover connection rows parsed")
        output, error = section(record, "list cm traffic-group")
        if error:
            reporter.add("ERROR", f"{prefix} masquerade configuration", error)
        else:
            try:
                groups = tmsh_objects(output, "cm traffic-group")
                group = next((body for name, body in groups.items()
                              if name.rsplit("/", 1)[-1].casefold() == "traffic-group-1"), None)
                mac = tmsh_property(group, "mac") if group is not None else None
                if not mac or not re.fullmatch(r"[\da-fA-F]{2}(?::[\da-fA-F]{2}){5}", mac):
                    reporter.add("FAIL", f"{prefix} masquerade configuration",
                                 "traffic-group-1 MAC missing or invalid")
                else:
                    observed_macs[side] = mac.casefold()
                    reporter.add("PASS" if int(mac[:2], 16) & 3 == 2 else "FAIL",
                                 f"{prefix} masquerade MAC format",
                                 f"mac={mac}; locally administered unicast required")
            except ValueError as exc:
                reporter.add("ERROR", f"{prefix} masquerade configuration", str(exc))
        output, error = section(record, "show sys hardware")
        if error:
            reporter.add("ERROR", f"{prefix} base MAC", error)
        else:
            try:
                base_candidates[side] = derive_masquerade_mac(hardware_base_mac(output))
            except ValueError as exc:
                reporter.add("ERROR", f"{prefix} base MAC", str(exc))
    if len(observed_macs) == 2:
        reporter.add("PASS" if len(set(observed_macs.values())) == 1 else "FAIL",
                     "Target pair masquerade MAC consistency", f"configured={observed_macs}")
    if observed_macs and base_candidates:
        if len(members) == 1 and next(iter(observed_macs.values())) not in base_candidates.values():
            reporter.add("WARN", "Target masquerade MAC derivation",
                         "Does not derive from selected member; peer base MAC not collected")
        elif len(members) == 2 and len(base_candidates) < 2:
            reporter.add("WARN", "Target masquerade MAC derivation",
                         "Peer base MAC unavailable; cannot rule out peer-derived masquerade")
        else:
            matches = set(observed_macs.values()) <= set(base_candidates.values())
            reporter.add("PASS" if matches else "FAIL", "Target masquerade MAC derivation",
                         f"configured={observed_macs}; derived from members={base_candidates}")


def compare_platform(reporter: Reporter, side: str, expected: dict, observed: dict,
                     hostname_suffix: str) -> None:
    prefix = f"{side.upper()} F5OS"
    host = expected["rseries_host"]
    target = expected["target"]
    reporter.compare(f"{prefix} host hostname", host["expected_hostname"],
                     observed.get("hostname"), observed.get("hostname_error"),
                     casefold=True, hostname_suffix=hostname_suffix)
    reporter.compare(f"{prefix} host management IP", host["management_ip"],
                     observed.get("management_ip"), observed.get("management_ip_error"))
    reporter.compare(f"{prefix} host product", host["model"],
                     observed.get("model"), observed.get("model_error"), casefold=True)
    tenant = observed.get("tenant")
    if tenant is None:
        reporter.add("ERROR", f"{prefix} tenant lookup", observed.get("tenant_error", "No tenant output"))
        return
    reporter.compare(f"{prefix} tenant name", target["tenant_name"], tenant.get("name"), casefold=True)
    reporter.compare(f"{prefix} tenant management IP", target["management_ip"], tenant.get("mgmt-ip"))
    reporter.compare(f"{prefix} prefix length", target["management_prefix_length"], tenant.get("prefix-length"))
    reporter.compare(f"{prefix} gateway", target["management_gateway"], tenant.get("gateway"))
    reporter.compare(f"{prefix} running version", target["software"]["version"], tenant.get("running_version"))
    reporter.compare(f"{prefix} running build", target["software"]["build"], tenant.get("running_build"))
    reporter.compare(f"{prefix} vCPUs", target["tenant"]["vcpu"], tenant.get("vcpu-cores-per-node"))
    reporter.compare(f"{prefix} type", "BIG-IP", tenant.get("type"), casefold=True)
    reporter.compare(f"{prefix} deployment", "deployed", tenant.get("running-state"), casefold=True)
    reporter.compare(f"{prefix} status", "Running", tenant.get("status"), casefold=True)
    if target["tenant"].get("fips_keys") is not None:
        reporter.compare(f"{prefix} FIPS partition", target["tenant"]["fips_partition_name"],
                         tenant.get("fips-partition"), casefold=True)
        reporter.compare(f"{prefix} QAT VF count", target["tenant"]["fips_accelerator_devices"],
                         tenant.get("qat-vf-count"))
        partition = observed.get("fips_partitions", {}).get(target["tenant"]["fips_partition_name"].casefold())
        reporter.compare(f"{prefix} FIPS key capacity", target["tenant"]["fips_keys"],
                         partition.get("keys") if partition else None,
                         observed.get("fips_error") or ("FIPS partition missing from show fips" if not partition else None))
        reporter.compare(f"{prefix} FIPS accelerator capacity", target["tenant"]["fips_accelerator_devices"],
                         partition.get("accelerator_devices") if partition else None,
                         observed.get("fips_error") or ("FIPS partition missing from show fips" if not partition else None))
    else:
        reporter.add("SKIP", f"{prefix} FIPS", "Not applicable for this host model")


def network_name(name: str) -> str:
    return name.rsplit("/", 1)[-1]


def named_network(name: str, marker: str) -> bool:
    return bool(re.search(r"(?:^|[-_])" + marker + r"(?:[-_]|$)", network_name(name), re.I))


def vlan_reference(vlans: dict[str, dict], name: str) -> dict | None:
    return vlans.get(name) or vlans.get("/Common/" + name)


def self_identity(entry: dict) -> str:
    return entry["address"].split("/", 1)[0]


def sync_tag(record: dict | None, candidates: list[str]) -> tuple[int | None, str | None, str | None]:
    """The lowest base MAC is the first currently deployed tenant on a host."""
    output, error = section(record, "show tenants | nomore")
    if error:
        return None, error, None
    tenants = f5os_tenants(output)
    if not tenants:
        return None, "No F5OS tenants found for SYNC VLAN ordering", None
    macs: dict[str, int] = {}
    for tenant in tenants:
        if tenant.get("running-state", "deployed").casefold() != "deployed":
            continue
        mac = tenant.get("base_mac")
        normalized = re.sub(r"[:-]", "", mac or "")
        if not re.fullmatch(r"[0-9A-Fa-f]{12}", normalized):
            return None, f"F5OS base MAC missing or invalid for tenant {tenant['name']}; cannot assign SYNC tag", None
        macs[tenant["name"].casefold()] = int(normalized, 16)
    if len(set(macs.values())) != len(macs):
        return None, "F5OS tenants have duplicate base MACs; deployment order is ambiguous", None
    matching = [candidate.casefold() for candidate in candidates if candidate.casefold() in macs]
    if not matching:
        return None, "Manifest tenant not found in F5OS inventory for SYNC ordering", None
    rank = sorted(macs.values()).index(macs[matching[0]]) + 1
    return 4000 + rank, None, f"tenant={matching[0]} base-mac={macs[matching[0]]:012x} rank={rank}"


def compare_network(reporter: Reporter, side: str, source: dict | None,
                    target: dict | None, host: dict | None,
                    candidates: list[str]) -> None:
    src_vlans, src_vlan_error = network_data(source, "vlan")
    dst_vlans, dst_vlan_error = network_data(target, "vlan")
    src_self, src_self_error = network_data(source, "self")
    dst_self, dst_self_error = network_data(target, "self")
    for label, error in (("source VLAN", src_vlan_error), ("target VLAN", dst_vlan_error),
                         ("source self IP", src_self_error), ("target self IP", dst_self_error)):
        if error:
            reporter.add("ERROR", f"{side.upper()} {label} inventory", error)
    if any((src_vlan_error, dst_vlan_error, src_self_error, dst_self_error)):
        return
    assert src_vlans is not None and dst_vlans is not None
    assert src_self is not None and dst_self is not None
    src_tags: dict[str, str] = {}
    dst_tags: dict[str, str] = {}
    for role, vlans, by_tag in (("source", src_vlans, src_tags),
                                ("target", dst_vlans, dst_tags)):
        for name, vlan in vlans.items():
            tag = vlan["tag"]
            if tag in by_tag:
                reporter.add("ERROR", f"{side.upper()} {role} VLAN tag {tag}",
                             f"Ambiguous: {by_tag[tag]} and {name}")
            by_tag[tag] = name
    if len(src_tags) != len(src_vlans) or len(dst_tags) != len(dst_vlans):
        return

    hsm_tags = {entry["tag"] for name, entry in src_vlans.items() if named_network(name, "HSM")}
    peer_tags = {entry["tag"] for name, entry in src_vlans.items() if named_network(name, "PEER")}
    sync_names = [name for name in dst_vlans if named_network(name, "SYNC")]
    expected_sync, sync_error, sync_basis = sync_tag(host, candidates) if peer_tags else (None, None, None)
    if sync_error:
        reporter.add("ERROR", f"{side.upper()} SYNC VLAN deployment order", sync_error)
    elif sync_basis:
        reporter.add("INFO", f"{side.upper()} SYNC VLAN deployment order", sync_basis)
    for name, vlan in src_vlans.items():
        tag = vlan["tag"]
        label = f"{side.upper()} VLAN {name} tag {tag}"
        match = dst_tags.get(tag)
        if tag in hsm_tags:
            reporter.add("FAIL" if match else "PASS", f"{label} HSM exclusion",
                         f"HSM tag present on target as {match}" if match else "HSM tag absent from target")
        elif tag in peer_tags:
            reporter.add("FAIL" if match else "PASS", f"{label} PEER exclusion",
                         f"PEER tag remains on target as {match}" if match else "PEER tag replaced")
        elif not match:
            reporter.add("FAIL", label, "Source VLAN tag absent from target")
        else:
            reporter.add("PASS", label, f"matched target VLAN {match}")
            expected_name = f"{network_name(name)}-{tag}"
            reporter.add("PASS" if network_name(match).casefold() == expected_name.casefold() else "WARN",
                         f"{label} target name", f"expected={expected_name!r} actual={network_name(match)!r}")
            for setting in sorted(vlan["failsafe"].keys() | dst_vlans[match]["failsafe"].keys()):
                original = vlan["failsafe"].get(setting)
                migrated = dst_vlans[match]["failsafe"].get(setting)
                reporter.add("PASS" if original == migrated else "WARN", f"{label} {setting}",
                             f"source={original!r} target={migrated!r}")
    for name, vlan in dst_vlans.items():
        tag = vlan["tag"]
        if named_network(name, "HSM"):
            reporter.add("FAIL", f"{side.upper()} target HSM VLAN {name}", "HSM VLAN must not be present")
        elif named_network(name, "PEER"):
            reporter.add("FAIL", f"{side.upper()} target PEER VLAN {name}", "PEER must be replaced with SYNC")
        elif tag not in src_tags and name not in sync_names:
            reporter.add("WARN", f"{side.upper()} target VLAN {name}", "No source VLAN with this tag")
    if peer_tags:
        if len(sync_names) != 1:
            reporter.add("FAIL", f"{side.upper()} SYNC VLAN", f"Expected one SYNC VLAN, found {sync_names}")
        elif expected_sync is not None:
            name = sync_names[0]
            reporter.compare(f"{side.upper()} SYNC VLAN tag (MAC rank)",
                             expected_sync, dst_vlans[name]["tag"])
            expected_name = f"SYNC-VLAN-{expected_sync}"
            actual_name = network_name(name)
            reporter.add("PASS" if expected_name.casefold() == actual_name.casefold() else "WARN",
                         f"{side.upper()} SYNC VLAN name",
                         f"expected={expected_name!r} actual={actual_name!r}")

    src_ips: dict[str, str] = {}
    dst_ips: dict[str, str] = {}
    for role, entries, by_ip in (("source", src_self, src_ips), ("target", dst_self, dst_ips)):
        for name, entry in entries.items():
            key = self_identity(entry)
            if key in by_ip:
                reporter.add("ERROR", f"{side.upper()} {role} self IP {key}",
                             f"Ambiguous: {by_ip[key]} and {name}")
            by_ip[key] = name
    if len(src_ips) != len(src_self) or len(dst_ips) != len(dst_self):
        return
    for name, entry in src_self.items():
        ip = self_identity(entry)
        vlan = vlan_reference(src_vlans, entry["vlan"])
        if vlan is None:
            reporter.add("ERROR", f"{side.upper()} source self {name}",
                         f"Referenced VLAN {entry['vlan']!r} missing from inventory")
            continue
        tag = vlan["tag"]
        peer = tag in peer_tags
        hsm = tag in hsm_tags or named_network(name, "HSM")
        match = dst_ips.get(ip)
        label = f"{side.upper()} self {ip} ({name})"
        if hsm:
            reporter.add("FAIL" if match else "PASS", f"{label} HSM exclusion",
                         f"HSM address present on target as {match}" if match else "HSM address absent from target")
            continue
        if not match:
            reporter.add("FAIL", label, "PEER self IP address absent from target SYNC VLAN"
                         if peer else "Source self IP address absent from target")
            continue
        reporter.add("PASS", label, f"matched target self IP {match}")
        dst_entry = dst_self[match]
        dst_vlan = vlan_reference(dst_vlans, dst_entry["vlan"])
        if dst_vlan is None:
            reporter.add("ERROR", f"{label} VLAN", f"Target VLAN {dst_entry['vlan']!r} missing")
        elif peer:
            on_sync = any(dst_vlan is dst_vlans[sync_name] for sync_name in sync_names)
            reporter.add("PASS" if on_sync else "FAIL", f"{label} PEER to SYNC VLAN",
                         f"target={dst_entry['vlan']!r} tag={dst_vlan['tag']}"
                         + ("" if on_sync else "; address must be on the target SYNC VLAN"))
        else:
            reporter.compare(f"{label} VLAN tag", tag, dst_vlan["tag"])
        original = entry["properties"]
        migrated = dst_entry["properties"]
        for field in sorted(original):
            if field == "vlan":
                continue  # The VLAN is compared by numeric tag above.
            old = original[field]
            new = migrated.get(field)
            if field == "traffic-group":
                old = network_name(str(old))
                new = network_name(str(new)) if new is not None else None
            if new is None:
                reporter.add("FAIL", f"{label} {field}", f"Source property {old!r} absent from target")
            elif field == "allow-service" and isinstance(old, (tuple, list)) and isinstance(new, (tuple, list)):
                reporter.compare_items(f"{label} {field}", old, new)
            else:
                reporter.compare(f"{label} {field}", old, new)
        # A floating self IP can be represented by either the explicit flag
        # or its traffic group; check the effective state even if the flag is omitted.
        for role, properties in (("source", original), ("target", migrated)):
            if properties.get("floating") not in (None, "enabled", "disabled"):
                reporter.add("ERROR", f"{label} {role} floating", "Unrecognized floating value")
        old_floating = original.get("floating", "disabled") == "enabled" or (
            network_name(str(original.get("traffic-group", ""))) != "traffic-group-local-only")
        new_floating = migrated.get("floating", "disabled") == "enabled" or (
            network_name(str(migrated.get("traffic-group", ""))) != "traffic-group-local-only")
        reporter.compare(f"{label} effective floating", old_floating, new_floating)
    sync_vlan_tags = {dst_vlans[name]["tag"] for name in sync_names}
    for name, entry in dst_self.items():
        ip = self_identity(entry)
        vlan = vlan_reference(dst_vlans, entry["vlan"])
        if vlan is None:
            reporter.add("ERROR", f"{side.upper()} target self {name}",
                         f"Referenced VLAN {entry['vlan']!r} missing from inventory")
        elif named_network(name, "HSM") or named_network(entry["vlan"], "HSM") or vlan["tag"] in hsm_tags:
            reporter.add("FAIL", f"{side.upper()} target HSM self {name}", "HSM self IP must not be present")
        elif ip not in src_ips and vlan["tag"] not in sync_vlan_tags:
            reporter.add("WARN", f"{side.upper()} target self {name}", "No source self IP with this address")
    if peer_tags and len(sync_names) == 1:
        sync_vlan_tag = dst_vlans[sync_names[0]]["tag"]
        sync_ips = [name for name, entry in dst_self.items()
                    if (vlan := vlan_reference(dst_vlans, entry["vlan"])) and vlan["tag"] == sync_vlan_tag]
        reporter.add("PASS" if sync_ips else "FAIL", f"{side.upper()} SYNC self IP",
                     f"target={sync_ips}" if sync_ips else "No target self IP on SYNC VLAN")


def compare_routes(reporter: Reporter, side: str, source: dict | None,
                   target: dict | None, target_management_gateway: str) -> None:
    for kind in ROUTE_COMMANDS:
        old, old_error = route_data(source, kind)
        new, new_error = route_data(target, kind)
        for role, error in (("source", old_error), ("target", new_error)):
            if error:
                reporter.add("ERROR", f"{side.upper()} {role} {kind} route inventory", error)
        if old_error or new_error:
            continue
        assert old is not None and new is not None
        if not old and not new:
            reporter.add("PASS", f"{side.upper()} {kind} routes", "No configured routes on either device")
        for destination, route in sorted(old.items()):
            label = f"{side.upper()} {kind} route {destination}"
            if destination not in new:
                reporter.add("FAIL", label, f"Source route {route['name']} missing from target")
                continue
            migrated = new[destination]
            reporter.add("PASS", label, f"source={route['name']} target={migrated['name']}")
            for setting in sorted(route["settings"].keys() | migrated["settings"].keys()):
                if kind == "management" and setting == "gateway":
                    continue  # Every target gateway is checked against the manifest below.
                original = route["settings"].get(setting)
                actual = migrated["settings"].get(setting)
                reporter.add("PASS" if original == actual else "FAIL" if kind == "traffic" else "WARN",
                             f"{label} {setting}",
                             f"source={original!r} target={actual!r}")
        for destination, route in sorted(new.items()):
            if destination not in old:
                reporter.add("FAIL" if kind == "traffic" else "WARN",
                             f"{side.upper()} target {kind} route {destination}",
                             f"No source route for {route['name']}; review route mapping")
            if kind == "management":
                gateway = route["settings"].get("gateway")
                reporter.add("PASS" if gateway == target_management_gateway else "FAIL",
                             f"{side.upper()} management route {destination} gateway",
                             f"expected target management gateway={target_management_gateway!r} "
                             f"actual={gateway!r}"
                             + (f" source={old[destination]['settings'].get('gateway')!r}"
                                if destination in old else ""))


def compare_system(reporter: Reporter, side: str, source: dict | None,
                   target: dict | None) -> None:
    for kind in SYSTEM_COMMANDS:
        old, old_error = system_data(source, kind)
        new, new_error = system_data(target, kind)
        for role, error in (("source", old_error), ("target", new_error)):
            if error:
                reporter.add("ERROR", f"{side.upper()} {role} {kind} config", error)
        if old_error or new_error:
            continue
        assert old is not None and new is not None
        for setting in sorted(old.keys() | new.keys()):
            original, actual = old.get(setting), new.get(setting)
            if kind == "ntp" and setting == "timezone":
                reporter.add("PASS" if actual == "UTC" else "FAIL",
                             f"{side.upper()} target ntp timezone",
                             f"expected='UTC' actual={actual!r} source={original!r}")
                continue
            if original is None and actual is None:
                continue
            status = "PASS" if original == actual else "WARN"
            reporter.add(status,
                         f"{side.upper()} {kind} {setting}",
                         f"source={original!r} target={actual!r}")


def object_path(name: str) -> str:
    return name if name.startswith("/") else "/Common/" + name


def virtual_endpoint(name: str, entry: dict) -> tuple[str, ...]:
    fields = entry["fields"]
    partition = object_path(name).rsplit("/", 1)[0]
    return (partition, str(entry["destination"]), str(entry["protocol"]),
            str(fields.get("source", "0.0.0.0/0")), str(fields.get("mask", "")))


def virtual_vlan_tags(name: str, fields: dict, vlans: dict[str, dict]) -> tuple[str, ...]:
    """Resolve a virtual's VLAN list to tags, preserving duplicate references."""
    references = fields.get("vlans")
    if not references or references in ("none", "default"):
        return ()
    if not isinstance(references, tuple):
        raise ValueError(f"Unrecognized VLAN list {references!r}")
    partition = object_path(name).rsplit("/", 1)[0]
    tags = []
    for reference in references:
        if reference in ("none", "default"):
            continue
        vlan = (vlans.get(reference) or vlans.get(f"{partition}/{reference}")
                or vlan_reference(vlans, reference))
        if vlan is None:
            raise ValueError(f"Referenced VLAN {reference!r} absent from VLAN inventory")
        tags.append(str(vlan["tag"]))
    return tuple(sorted(tags, key=lambda tag: (int(tag) if tag.isdigit() else -1, tag)))


def compare_applications(reporter: Reporter, side: str, source: dict | None,
                         target: dict | None) -> None:
    inventories: dict[str, tuple[dict[str, dict], dict[str, dict]]] = {}
    for kind in APPLICATION_COMMANDS:
        old, old_error = application_data(source, kind)
        new, new_error = application_data(target, kind)
        for role, error in (("source", old_error), ("target", new_error)):
            if error:
                reporter.add("ERROR", f"{side.upper()} {role} {kind} inventory", error)
        if old_error or new_error:
            continue
        assert old is not None and new is not None
        inventories[kind] = (old, new)
        if not old and not new:
            reporter.add("PASS", f"{side.upper()} {kind} inventory", "No configured objects on either device")

    if "virtual" in inventories:
        old, new = inventories["virtual"]
        vlan_inventories: tuple[dict[str, dict], dict[str, dict]] | None = None
        if any(isinstance(entry["fields"].get("vlans"), tuple)
               and entry["fields"]["vlans"] for entry in (*old.values(), *new.values())):
            src_vlans, src_error = network_data(source, "vlan")
            dst_vlans, dst_error = network_data(target, "vlan")
            for role, error in (("source", src_error), ("target", dst_error)):
                if error:
                    reporter.add("ERROR", f"{side.upper()} {role} virtual VLAN inventory", error)
            if not src_error and not dst_error:
                assert src_vlans is not None and dst_vlans is not None
                vlan_inventories = src_vlans, dst_vlans
        by_endpoint: dict[tuple[str, ...], list[str]] = {}
        for name, entry in new.items():
            by_endpoint.setdefault(virtual_endpoint(name, entry), []).append(name)
        matched: set[str] = set()
        for name, entry in sorted(old.items()):
            exact = next((candidate for candidate in new if object_path(candidate) == object_path(name)), None)
            candidates = by_endpoint.get(virtual_endpoint(name, entry), [])
            if exact:
                target_name = exact
            elif len(candidates) == 1 and candidates[0] not in matched:
                target_name = candidates[0]
            elif len(candidates) > 1:
                reporter.add("ERROR", f"{side.upper()} virtual {name}",
                             f"Ambiguous target endpoint: {candidates}")
                continue
            else:
                reporter.add("FAIL", f"{side.upper()} virtual {name}",
                             f"Missing from target; source destination={entry['destination']!r}")
                continue
            if target_name in matched:
                reporter.add("ERROR", f"{side.upper()} virtual {name}",
                             f"Target virtual {target_name} matched multiple source virtuals")
                continue
            matched.add(target_name)
            label = f"{side.upper()} virtual {name}"
            reporter.add("PASS" if object_path(name) == object_path(target_name) else "WARN",
                         label, f"target={target_name} destination={entry['destination']}")
            src_fields, dst_fields = entry["fields"], new[target_name]["fields"]
            for field in ("destination", "ip-protocol", "source", "mask", "pool", "disabled", "enabled",
                          "dhcp-relay", "ip-forward", "internal", "l2-forward", "reject",
                          "policies", "translate-address", "translate-port"):
                before, after = src_fields.get(field), dst_fields.get(field)
                if field == "pool":
                    before = object_path(str(before)) if before not in (None, "none") else before
                    after = object_path(str(after)) if after not in (None, "none") else after
                if before != after:
                    reporter.add("FAIL", f"{label} {field}", f"source={before!r} target={after!r}")
            if vlan_inventories is not None and ("vlans" in src_fields or "vlans" in dst_fields):
                try:
                    before_tags = virtual_vlan_tags(name, src_fields, vlan_inventories[0])
                    after_tags = virtual_vlan_tags(target_name, dst_fields, vlan_inventories[1])
                    reporter.add("PASS" if before_tags == after_tags else "FAIL",
                                 f"{label} VLAN tags",
                                 f"source={before_tags!r} target={after_tags!r}")
                except ValueError as exc:
                    reporter.add("ERROR", f"{label} VLAN tags", str(exc))
            for field in ("profiles", "rules", "persist", "fallback-persistence",
                          "source-address-translation", "vlans-enabled", "vlans-disabled"):
                before, after = src_fields.get(field), dst_fields.get(field)
                if before != after:
                    reporter.add("WARN", f"{label} {field}", f"source={before!r} target={after!r}")
        for name in sorted(new.keys() - matched):
            reporter.add("WARN", f"{side.upper()} target virtual {name}",
                         "No matching source virtual; review target-only configuration")

    if "pool" in inventories:
        old, new = inventories["pool"]
        by_path = {object_path(name): name for name in new}
        matched = set()
        for name, entry in sorted(old.items()):
            target_name = by_path.get(object_path(name))
            label = f"{side.upper()} pool {name}"
            if target_name is None:
                reporter.add("FAIL", label, "Source pool missing from target")
                continue
            matched.add(target_name)
            reporter.add("PASS", label, f"target={target_name}")
            migrated = new[target_name]
            src_members, dst_members = entry["members"], migrated["members"]
            for identity, member in sorted(src_members.items()):
                target_member = dst_members.get(identity)
                if target_member is None:
                    reporter.add("FAIL", f"{label} member {identity}",
                                 f"Source member {member['name']} absent from target")
                    continue
                reporter.add("PASS", f"{label} member {identity}",
                             f"source={member['name']} target={target_member['name']}")
                for field in ("monitor", "session", "ratio", "priority-group"):
                    before = member["fields"].get(field)
                    after = target_member["fields"].get(field)
                    if before != after:
                        reporter.add("WARN", f"{label} member {identity} {field}",
                                     f"source={before!r} target={after!r}")
            for identity in sorted(dst_members.keys() - src_members.keys()):
                reporter.add("WARN", f"{label} target member {identity}",
                             "No source member at this address and port")
            for field in ("monitor", "load-balancing-mode", "min-active-members"):
                before, after = entry["fields"].get(field), migrated["fields"].get(field)
                if before != after:
                    reporter.add("WARN", f"{label} {field}", f"source={before!r} target={after!r}")
        for name in sorted(new.keys() - matched):
            reporter.add("WARN", f"{side.upper()} target pool {name}",
                         "No matching source pool; review target-only configuration")


REFERENCE_KINDS = {
    "http": (REFERENCE_COMMANDS["http"], "ltm profile http"),
    "tcp": (REFERENCE_COMMANDS["tcp"], "ltm profile tcp"),
    "fastl4": (REFERENCE_COMMANDS["fastl4"], "ltm profile fastl4"),
    "one_connect": (REFERENCE_COMMANDS["one_connect"], "ltm profile one-connect"),
    "snatpool": (REFERENCE_COMMANDS["snatpool"], "ltm snatpool"),
    "policy": (REFERENCE_COMMANDS["policy"], "ltm policy"),
    "cipher_group": (REFERENCE_COMMANDS["cipher_group"], "ltm cipher group"),
    "cipher_rule": (REFERENCE_COMMANDS["cipher_rule"], "ltm cipher rule"),
    "client_ssl": (CERTIFICATE_COMMANDS["client_ssl"], "ltm profile client-ssl"),
    "server_ssl": (CERTIFICATE_COMMANDS["server_ssl"], "ltm profile server-ssl"),
    "https_monitor": (CERTIFICATE_COMMANDS["https_monitor"], "ltm monitor https"),
}


def named_references(body: str, field: str) -> list[str]:
    block = tmsh_block(body, field)
    if block is None:
        value = tmsh_property(body, field)
        return [value] if value and value != "none" else []
    nested = tmsh_objects_from_block(block) if "{" in block else []
    if nested:
        return [name for name, _ in nested]
    return [token.strip('"') for token in re.findall(r'"(?:\\.|[^"\\])*"|[^\s{}]+', block)
            if token.strip('"') not in ("none", "default")]


def monitor_references(expression: str, owner: str) -> list[str]:
    """Read complete names in a tmsh pool/member monitor expression."""
    tokens = re.findall(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?|[A-Za-z_][A-Za-z0-9_.-]*",
                        expression)
    syntax = {"min", "of", "and", "or", "none", "default"}
    return [scoped_name(token, owner) for token in tokens if token.lower() not in syntax]


def paired_references(old_refs: list[str], new_refs: list[str], old_owner: str,
                      new_owner: str) -> list[tuple[str, str]]:
    """Prefer exact object identities, then match remaining intentional renames by position."""
    remaining = list(new_refs)
    pairs: list[tuple[str, str]] = []
    renamed: list[str] = []
    for old in old_refs:
        match = next((candidate for candidate in remaining
                      if scoped_name(candidate, new_owner) == scoped_name(old, old_owner)), None)
        if match is not None:
            pairs.append((old, match))
            remaining.remove(match)
        else:
            renamed.append(old)
    pairs.extend(zip(renamed, remaining))
    return pairs


def virtual_pairs(source: dict | None, target: dict | None,
                  reporter: Reporter, side: str) -> list[tuple[str, str]]:
    old, old_error = application_data(source, "virtual")
    new, new_error = application_data(target, "virtual")
    for role, error in (("source", old_error), ("target", new_error)):
        if error:
            reporter.add("ERROR", f"{side.upper()} {role} referenced VIP inventory", error)
    if old_error or new_error:
        return []
    assert old is not None and new is not None
    endpoints: dict[tuple[str, ...], list[str]] = {}
    for name, entry in new.items():
        endpoints.setdefault(virtual_endpoint(name, entry), []).append(name)
    pairs = []
    used = set()
    for name, entry in sorted(old.items()):
        exact = next((n for n in new if object_path(n) == object_path(name)), None)
        candidates = endpoints.get(virtual_endpoint(name, entry), [])
        partner = exact or (candidates[0] if len(candidates) == 1 else None)
        if partner is None or partner in used:
            reporter.add("ERROR" if len(candidates) > 1 else "FAIL",
                         f"{side.upper()} VIP references {name}",
                         f"No unique target VIP: {candidates}")
            continue
        used.add(partner)
        pairs.append((object_path(name), object_path(partner)))
    return pairs


def compare_references(reporter: Reporter, side: str, source: dict | None,
                       target: dict | None) -> None:
    """Compare the statically reachable configuration of migrated VIPs."""
    source_version = bigip_data(source).get("version")
    source_major = int(source_version.split(".", 1)[0]) if source_version else None
    inventories: dict[str, tuple[dict, dict]] = {}
    for kind, (command, header) in REFERENCE_KINDS.items():
        old, old_error = object_inventory(source, command, header)
        new, new_error = object_inventory(target, command, header)
        for role, error in (("source", old_error), ("target", new_error)):
            if error:
                reporter.add("ERROR", f"{side.upper()} {role} {kind} inventory", error)
        if old is not None and new is not None:
            inventories[kind] = (old, new)
    source_rules, source_error = rule_inventory(source)
    target_rules, target_error = rule_inventory(target)
    source_groups, group_error = data_group_inventory(source)
    target_groups, target_group_error = data_group_inventory(target)
    for label, error in (("source iRules", source_error), ("target iRules", target_error),
                         ("source data groups", group_error), ("target data groups", target_group_error)):
        if error:
            reporter.add("ERROR", f"{side.upper()} {label} inventory", error)

    visited_objects: set[tuple[str, str]] = set()
    visited_rules: set[tuple[str, str]] = set()
    visited_groups: set[tuple[str, str]] = set()

    def compare_object(kind: str, old_ref: str, new_ref: str, owner_old: str,
                       owner_new: str) -> tuple[str | None, str | None]:
        old_name = scoped_name(old_ref, owner_old)
        new_name = scoped_name(new_ref, owner_new)
        label = f"{side.upper()} {kind} {old_name}"
        if kind not in inventories:
            reporter.add("ERROR", label, "Inventory unavailable")
            return None, None
        old_objects, new_objects = inventories[kind]
        before, after = old_objects.get(old_name), new_objects.get(new_name)
        if before is None or after is None:
            reporter.add("FAIL", label, f"source={'present' if before is not None else 'missing'} "
                         f"target={'present' if after is not None else 'missing'} ({new_name})")
            return None, None
        if (kind, old_name) not in visited_objects:
            visited_objects.add((kind, old_name))
            if old_name != new_name:
                reporter.add("WARN", label, f"Renamed to {new_name}; checking attributes")
            try:
                # A certificate renewal can replace cert/key/chain identifiers.
                # Certificate semantics are compared separately below.
                old_fields = tmsh_fields(re.sub(r"\blast-modified\s+(?:\"[^\"]*\"|\S+)", "", before))
                new_fields = tmsh_fields(re.sub(r"\blast-modified\s+(?:\"[^\"]*\"|\S+)", "", after))
                for field in sorted(old_fields.keys() | new_fields.keys()):
                    value = old_fields.get(field)
                    if kind in ("client_ssl", "server_ssl") and field in {
                            "cert", "key", "chain", "cert-key-chain", "ca-file", "trusted-cert-authority",
                            "crl-file", "cipher-group", "inherit-ca-certkeychain",
                            "revoked-cert-status-response-control"}:
                        continue
                    if kind in ("client_ssl", "server_ssl") and field == "options":
                        target_value = new_fields.get(field)
                        if isinstance(value, (tuple, type(None))) and isinstance(target_value, (tuple, type(None))):
                            old_options = value or ()
                            new_options = target_value or ()
                            if Counter(old_options) == Counter(new_options):
                                continue
                            old_option_set, new_option_set = set(old_options), set(new_options)
                            expected = {"no-tlsv1.3", "no-dtlsv1.2", "no-tls1.3", "no-dtls1.2"}
                            conversion = (source_major is not None and source_major < 14 and
                                          not (old_option_set - new_option_set) and
                                          bool(new_option_set - old_option_set) and
                                          (new_option_set - old_option_set) <= expected)
                            if conversion:
                                reporter.compare_items(f"{label} options", old_options, new_options, status="WARN")
                                reporter.add("INFO", f"{label} options conversion",
                                             f"Source BIG-IP {source_version}: migration adds TLS 1.3 / DTLS 1.2 "
                                             "exclusions because TLS 1.3 was introduced in newer releases")
                            else:
                                reporter.compare_items(f"{label} options", old_options, new_options)
                            continue
                    if isinstance(value, (tuple, type(None))) and isinstance(new_fields.get(field), tuple):
                        if value != new_fields[field]:
                            reporter.compare_items(f"{label} {field}", value or (), new_fields[field])
                        continue
                    if isinstance(value, tuple) and new_fields.get(field) is None:
                        reporter.compare_items(f"{label} {field}", value, ())
                        continue
                    if value != new_fields.get(field):
                        reporter.add("FAIL", f"{label} {field}",
                                     f"source={value!r} target={new_fields.get(field)!r}")
                if not any(status in ("FAIL", "WARN") and entry.startswith(label + " ")
                           for status, entry, _ in reporter.results):
                    reporter.add("PASS", label, f"Target {new_name}: source attributes match")
            except ValueError as exc:
                reporter.add("ERROR", label, str(exc))
            if kind in ("http", "tcp", "fastl4", "one_connect", "client_ssl", "server_ssl"):
                parent_old, parent_new = tmsh_property(before, "defaults-from"), tmsh_property(after, "defaults-from")
                if parent_old and parent_new and scoped_name(parent_old, old_name) != old_name:
                    if scoped_name(parent_old, old_name) in inventories[kind][0]:
                        compare_object(kind, parent_old, parent_new, old_name, new_name)
                    else:
                        reporter.add("WARN", f"{label} defaults-from",
                                     "Parent profile not in collected family; inherited settings unverified")
            if kind in ("client_ssl", "server_ssl"):
                old_cipher = tmsh_property(before, "cipher-group")
                new_cipher = tmsh_property(after, "cipher-group")
                if old_cipher and old_cipher != "none":
                    if new_cipher and new_cipher != "none":
                        compare_object("cipher_group", old_cipher, new_cipher, old_name, new_name)
                    else:
                        reporter.add("FAIL", f"{label} cipher-group", "Cipher group missing from target")
            if kind == "cipher_group":
                for field in ("allow", "exclude", "require"):
                    old_refs, new_refs = named_references(before, field), named_references(after, field)
                    if len(old_refs) != len(new_refs):
                        reporter.add("FAIL", f"{label} {field}",
                                     f"source={old_refs} target={new_refs}")
                    for old_rule, new_rule in paired_references(old_refs, new_refs, old_name, new_name):
                        compare_object("cipher_rule", old_rule, new_rule, old_name, new_name)
        return before, after

    def compare_group(old_ref: str, new_ref: str, old_owner: str, new_owner: str) -> None:
        old_name, new_name = scoped_name(old_ref, old_owner), scoped_name(new_ref, new_owner)
        if (old_name, new_name) in visited_groups:
            return
        visited_groups.add((old_name, new_name))
        label = f"{side.upper()} data-group {old_name}"
        if source_groups is None or target_groups is None:
            reporter.add("ERROR", label, "Data-group inventory unavailable")
            return
        before, after = source_groups.get(old_name), target_groups.get(new_name)
        if before is None:
            reporter.add("WARN", label,
                         "Referenced name absent from source data-group inventory; verify iRule syntax or inventory")
        elif after is None:
            reporter.add("FAIL", label, "Source data group absent on target")
        else:
            if before == after:
                reporter.add("PASS", label, f"target={new_name} records match")
            else:
                before_fields, after_fields = before["fields"], after["fields"]
                for field in sorted(before_fields.keys() | after_fields.keys()):
                    old_value, new_value = before_fields.get(field), after_fields.get(field)
                    if old_value == new_value:
                        continue
                    if field == "records":
                        reporter.compare_items(f"{label} records", old_value or (), new_value or ())
                    elif isinstance(old_value, tuple) and isinstance(new_value, tuple):
                        reporter.compare_items(f"{label} {field}", old_value, new_value)
                    else:
                        reporter.add("FAIL", f"{label} {field}",
                                     f"source={reporter.red(repr(old_value))} target={reporter.red(repr(new_value))}")
                if before["subtype"] != after["subtype"]:
                    reporter.add("FAIL", f"{label} subtype",
                                 f"source={before['subtype']} target={after['subtype']}")

    def compare_rule(old_ref: str, new_ref: str, old_owner: str, new_owner: str,
                     depth: int = 0) -> None:
        old_name, new_name = scoped_name(old_ref, old_owner), scoped_name(new_ref, new_owner)
        label = f"{side.upper()} iRule {old_name}"
        if (old_name, new_name) in visited_rules:
            return
        visited_rules.add((old_name, new_name))
        if source_rules is None or target_rules is None:
            reporter.add("ERROR", label, "iRule inventory unavailable")
            return
        before, after = source_rules.get(old_name), target_rules.get(new_name)
        if before is None or after is None:
            reporter.add("FAIL", label, f"source={'present' if before is not None else 'missing'} "
                         f"target={'present' if after is not None else 'missing'} ({new_name})")
            return
        old_hash, new_hash = rule_digest(before), rule_digest(after)
        reporter.add("PASS" if old_hash == new_hash else "FAIL", label,
                     f"source MD5={old_hash} target MD5={new_hash}" +
                     (f" target={new_name}" if old_name != new_name else ""))
        old_rules, old_groups, old_unresolved = rule_dependencies(before)
        new_rules, new_groups, new_unresolved = rule_dependencies(after)
        for item in sorted(old_unresolved | new_unresolved):
            reporter.add("WARN", f"{label} dependency", f"Cannot resolve {item}")
        for group in sorted(old_groups | new_groups):
            if group not in old_groups or group not in new_groups:
                reporter.add("FAIL", f"{label} data-group {group}", "Reference differs across devices")
            else:
                compare_group(group, group, old_name, new_name)
        for dependency in sorted(old_rules | new_rules):
            if dependency not in old_rules or dependency not in new_rules:
                reporter.add("FAIL", f"{label} call {dependency}", "Reference differs across devices")
            elif depth >= 10:
                reporter.add("WARN", f"{label} call {dependency}", "Unverified: iRule depth limit (10)")
            else:
                compare_rule(dependency, dependency, old_name, new_name, depth + 1)

    pairs = virtual_pairs(source, target, reporter, side)
    if not pairs:
        return
    old_vips, old_error = object_inventory(source, APPLICATION_COMMANDS["virtual"], "ltm virtual")
    new_vips, new_error = object_inventory(target, APPLICATION_COMMANDS["virtual"], "ltm virtual")
    if old_error or new_error:
        reporter.add("ERROR", f"{side.upper()} VIP references", old_error or new_error or "")
        return
    assert old_vips is not None and new_vips is not None
    for old_vip, new_vip in pairs:
        old_body, new_body = old_vips[old_vip], new_vips[new_vip]
        for kind, property_name in (("profile", "profiles"), ("policy", "policies"), ("rule", "rules")):
            old_refs = named_references(old_body, property_name)
            new_refs = named_references(new_body, property_name)
            if len(old_refs) != len(new_refs):
                reporter.add("FAIL", f"{side.upper()} VIP {old_vip} {property_name}",
                             f"source={old_refs} target={new_refs}")
            for old_ref, new_ref in paired_references(old_refs, new_refs, old_vip, new_vip):
                if kind == "rule":
                    compare_rule(old_ref, new_ref, old_vip, new_vip)
                elif kind == "policy":
                    compare_object("policy", old_ref, new_ref, old_vip, new_vip)
                else:
                    profile_kind = next((candidate for candidate in ("http", "tcp", "fastl4", "one_connect", "client_ssl", "server_ssl")
                                         if candidate in inventories and
                                         scoped_name(old_ref, old_vip) in inventories[candidate][0]), None)
                    if profile_kind:
                        compare_object(profile_kind, old_ref, new_ref, old_vip, new_vip)
                    else:
                        reporter.add("WARN", f"{side.upper()} VIP {old_vip} profile {old_ref}",
                                     "Profile family not collected; attributes unverified")
        old_sat = tmsh_block(old_body, "source-address-translation")
        new_sat = tmsh_block(new_body, "source-address-translation")
        old_pool = tmsh_property(old_sat or "", "pool")
        new_pool = tmsh_property(new_sat or "", "pool")
        if old_pool or new_pool:
            if not old_pool or not new_pool:
                reporter.add("FAIL", f"{side.upper()} VIP {old_vip} SNAT pool",
                             f"source={old_pool!r} target={new_pool!r}")
            else:
                compare_object("snatpool", old_pool, new_pool, old_vip, new_vip)


def profile_cert_slots(body: str) -> list[dict]:
    block = tmsh_block(body, "cert-key-chain")
    slots: list[dict] = []
    if block is not None:
        slots = [{"slot": slot, "cert": tmsh_property(contents, "cert"),
                  "key": tmsh_property(contents, "key"),
                  "chain": tmsh_property(contents, "chain"),
                  "attributes": {field: value for field, value in tmsh_fields(contents).items()
                                 if field not in {"cert", "key", "chain"}}}
                 for slot, contents in tmsh_objects_from_block(block)]
    # Top-level cert/key/chain fields often mirror a cert-key-chain slot. They
    # may also be independent references and must not disappear in that case.
    fields = tmsh_fields(body)
    standalone = {field: fields.get(field) for field in ("cert", "key", "chain")}
    supplied = {field: value for field, value in standalone.items() if value not in (None, "none")}
    if supplied and not any(all(slot[field] == value for field, value in supplied.items()) for slot in slots):
        slots.append({"slot": "top-level" if slots else "default", **standalone,
                      "attributes": {}})
    return slots


def certificate_properties(body: str) -> dict[str, str | None]:
    names = ("subject", "issuer", "subject-alternative-name", "key-type",
             "certificate-key-size", "certificate-key-curve-name", "cert-type",
             "version", "expiration-date", "expiration-string", "serial-number", "fingerprint")
    return {name: tmsh_property(body, name) for name in names}


def san_items(value: str | None) -> tuple[str, ...]:
    """Preserve SAN types and multiplicity while ignoring presentation order."""
    if not value or value.casefold() == "none":
        return ()
    items = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        kind, sep, name = item.partition(":")
        items.append(f"{kind.upper()}:{name.casefold()}" if sep and kind.casefold() == "dns" else
                     f"{kind.upper()}:{name}" if sep else item)
    return tuple(items)


def certificate_cn(subject: str | None) -> str | None:
    if not subject:
        return None
    match = re.search(r"(?:^|,)\s*CN\s*=\s*([^,]+)", subject, re.I)
    return match.group(1).strip() if match else None


def certificate_expiry(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_migration_date(value: str | None) -> datetime | None:
    if not isinstance(value, str):
        return None
    for format_string in ("%Y-%m-%d", "%d-%B-%Y", "%d-%b-%Y"):
        try:
            return datetime.strptime(value.strip(), format_string).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def load_issuer_upgrades(path: Path | None) -> set[tuple[str, str]]:
    """Load approved CA renewals from a local, untracked JSON file."""
    if path is None:
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(
            isinstance(entry, dict) and isinstance(entry.get("source_cn"), str)
            and isinstance(entry.get("target_cn"), str) and entry["source_cn"].strip()
            and entry["target_cn"].strip() for entry in data):
        raise ValueError("Issuer upgrade map must be a JSON array of source_cn/target_cn pairs")
    return {(entry["source_cn"].strip(), entry["target_cn"].strip()) for entry in data}


def allowed_issuer_upgrade(source: str | None, target: str | None,
                           approved: set[tuple[str, str]]) -> bool:
    old_cn, new_cn = certificate_cn(source), certificate_cn(target)
    if not source or not target or not old_cn or not new_cn or (old_cn, new_cn) not in approved:
        return False
    # The renewed CA name may appear in both CN and OU. Only the approved
    # name replacement is allowed; every other DN component must stay equal.
    return source.replace(old_cn, new_cn) == target


def is_default_file(ref: str | None, suffix: str) -> bool:
    return bool(ref and ref.rsplit("/", 1)[-1].casefold() == "default." + suffix)


def bundle_members(body: str) -> tuple[tuple[str, str | None], ...] | None:
    block = tmsh_block(body, "bundle-certificates")
    if block is None:
        return None
    members = [(tmsh_property(row, "fingerprint"), certificate_cn(tmsh_property(row, "subject")))
               for _, row in tmsh_objects_from_block(block)]
    if not members or any(not fingerprint for fingerprint, _ in members):
        return None
    return tuple(sorted(members, key=lambda member: member[0]))


def compare_certificates(reporter: Reporter, side: str, source: dict | None,
                         target: dict | None, migration_date: str | None = None,
                         issuer_upgrades: set[tuple[str, str]] | None = None) -> None:
    """Trace only SSL on migrated VIPs and HTTPS monitors attached to their pools."""
    migrated_at = parse_migration_date(migration_date)
    issuer_upgrades = issuer_upgrades or set()
    inventories: dict[str, tuple[dict[str, str], dict[str, str]]] = {}
    kinds = {
        "client_ssl": (CERTIFICATE_COMMANDS["client_ssl"], "ltm profile client-ssl"),
        "server_ssl": (CERTIFICATE_COMMANDS["server_ssl"], "ltm profile server-ssl"),
        "https_monitor": (CERTIFICATE_COMMANDS["https_monitor"], "ltm monitor https"),
        "cert": (CERTIFICATE_COMMANDS["cert"], "sys file ssl-cert"),
        "key": (CERTIFICATE_COMMANDS["key"], "sys file ssl-key"),
        "bundle": (CERTIFICATE_COMMANDS["bundle"], "sys file ssl-cert"),
        "cipher_group": (REFERENCE_COMMANDS["cipher_group"], "ltm cipher group"),
        "cipher_rule": (REFERENCE_COMMANDS["cipher_rule"], "ltm cipher rule"),
    }
    for kind, (command, header) in kinds.items():
        old, old_error = object_inventory(source, command, header)
        new, new_error = object_inventory(target, command, header)
        for role, error in (("source", old_error), ("target", new_error)):
            if error:
                reporter.add("ERROR", f"{side.upper()} {role} {kind} inventory", error)
        if old is not None and new is not None:
            inventories[kind] = old, new
    # The separately tested virtual profile listing validates the relationship
    # collected by the full virtual inventory before we report attached certs.
    profile_lists: list[dict[str, str]] = []
    for role, record in (("source", source), ("target", target)):
        objects, error = object_inventory(record, CERTIFICATE_COMMANDS["virtual_profiles"],
                                          "ltm virtual")
        if error:
            reporter.add("ERROR", f"{side.upper()} {role} VIP SSL attachments", error)
        profile_lists.append(objects or {})
    pairs = virtual_pairs(source, target, reporter, side)
    if not pairs:
        return
    old_vips, old_error = object_inventory(source, APPLICATION_COMMANDS["virtual"], "ltm virtual")
    new_vips, new_error = object_inventory(target, APPLICATION_COMMANDS["virtual"], "ltm virtual")
    if old_error or new_error or old_vips is None or new_vips is None:
        reporter.add("ERROR", f"{side.upper()} VIP certificate graph", old_error or new_error or "Missing VIP inventory")
        return

    visited_profiles: set[tuple[str, str, str]] = set()
    visited_certs: set[tuple[str, str]] = set()
    visited_server_eku: set[tuple[str, str]] = set()
    visited_bundles: set[tuple[str, str]] = set()

    def compare_cipher_fields(label: str, before: str, after: str) -> None:
        old_fields, new_fields = tmsh_fields(before), tmsh_fields(after)
        if old_fields == new_fields:
            reporter.add("PASS", label, "Attributes match")
            return
        for field in sorted(old_fields.keys() | new_fields.keys()):
            old_value, new_value = old_fields.get(field), new_fields.get(field)
            if old_value == new_value:
                continue
            if field == "ciphers" and isinstance(old_value, str) and isinstance(new_value, str):
                reporter.compare_items(f"{label} {field}", old_value.split(":"),
                                       new_value.split(":"), ordered=True)
            elif isinstance(old_value, (tuple, type(None))) and isinstance(new_value, (tuple, type(None))):
                reporter.compare_items(f"{label} {field}", old_value or (), new_value or (), ordered=True)
            else:
                reporter.add("FAIL", f"{label} {field}",
                             f"source={reporter.red(repr(old_value))} target={reporter.red(repr(new_value))}")

    def compare_ciphers(old_ref: str | None, new_ref: str | None,
                        old_owner: str, new_owner: str) -> None:
        if not old_ref or old_ref == "none":
            return
        label = f"{side.upper()} SSL cipher group {old_ref}"
        if not new_ref or new_ref == "none":
            reporter.add("FAIL", label, "Cipher group missing on target")
            return
        if "cipher_group" not in inventories or "cipher_rule" not in inventories:
            reporter.add("ERROR", label, "Cipher group or rule inventory unavailable")
            return
        old_name, new_name = scoped_name(old_ref, old_owner), scoped_name(new_ref, new_owner)
        old_groups, new_groups = inventories["cipher_group"]
        before, after = old_groups.get(old_name), new_groups.get(new_name)
        if before is None or after is None:
            reporter.add("FAIL", label, f"source={'present' if before is not None else 'missing'} "
                         f"target={'present' if after is not None else 'missing'}")
            return
        compare_cipher_fields(label, before, after)
        old_rules, new_rules = inventories["cipher_rule"]
        for field in ("allow", "exclude", "require"):
            src_refs, dst_refs = named_references(before, field), named_references(after, field)
            if len(src_refs) != len(dst_refs):
                reporter.add("FAIL", f"{label} {field}", f"source={src_refs} target={dst_refs}")
            for src_ref, dst_ref in paired_references(src_refs, dst_refs, old_name, new_name):
                src_rule = old_rules.get(scoped_name(src_ref, old_name))
                dst_rule = new_rules.get(scoped_name(dst_ref, new_name))
                rule_label = f"{label} rule {src_ref}"
                if src_rule is None or dst_rule is None:
                    reporter.add("FAIL", rule_label, "Cipher rule absent from source or target inventory")
                else:
                    compare_cipher_fields(rule_label, src_rule, dst_rule)

    def compare_bundle(old_ref: str | None, new_ref: str | None,
                       old_owner: str, new_owner: str) -> None:
        if not old_ref or old_ref == "none":
            if new_ref and new_ref != "none":
                reporter.add("WARN", f"{side.upper()} CA/chain {new_ref}",
                             "Target has an additional CA/chain reference; review")
            return
        label = f"{side.upper()} CA/chain {old_ref}"
        if not new_ref or new_ref == "none":
            reporter.add("FAIL", label, "CA/chain missing on target")
            return
        if "bundle" not in inventories or "cert" not in inventories:
            reporter.add("ERROR", label, "Certificate or bundle inventory unavailable")
            return
        old_name, new_name = scoped_name(old_ref, old_owner), scoped_name(new_ref, new_owner)
        if (old_name, new_name) in visited_bundles:
            return
        visited_bundles.add((old_name, new_name))
        old_bundles, new_bundles = inventories["bundle"]
        old_certs, new_certs = inventories["cert"]
        old_body = old_bundles.get(old_name) or old_certs.get(old_name)
        new_body = new_bundles.get(new_name) or new_certs.get(new_name)
        if old_body is None or new_body is None:
            reporter.add("FAIL", label, f"source={'present' if old_body else 'missing'} "
                         f"target={'present' if new_body else 'missing'}")
            return
        old_members, new_members = bundle_members(old_body), bundle_members(new_body)
        if (old_members is None) != (new_members is None):
            reporter.add("FAIL", label, "Bundle membership exists on only one device")
            return
        if old_members is None and new_members is None:
            # Only a single certificate may use its own fingerprint. A bundle
            # with missing member metadata must never pass on the first cert.
            if (re.search(r"\bbundle-certificates\s+(?!none\b)", old_body) or
                    re.search(r"\bbundle-certificates\s+(?!none\b)", new_body)):
                reporter.add("WARN", label, "Bundle member fingerprints not available; unverified")
                return
            old_members = ((tmsh_property(old_body, "fingerprint") or "",
                            certificate_cn(tmsh_property(old_body, "subject"))),)
            new_members = ((tmsh_property(new_body, "fingerprint") or "",
                            certificate_cn(tmsh_property(new_body, "subject"))),)
        if not old_members or not new_members or any(not fingerprint for fingerprint, _ in (*old_members, *new_members)):
            reporter.add("WARN", label, "Bundle membership/fingerprint unavailable; unverified")
        else:
            source_counts = Counter(fingerprint for fingerprint, _ in old_members)
            target_counts = Counter(fingerprint for fingerprint, _ in new_members)
            matched = sum((source_counts & target_counts).values())
            missing, extra = source_counts - target_counts, target_counts - source_counts
            if not missing and not extra:
                reporter.add("PASS", label, f"{matched}/{len(old_members)} fingerprints match")
            else:
                standard_ca_bundle = any(os.path.basename(ref).casefold() == "ca-bundle.crt"
                                         for ref in (old_name, new_name))
                source_cn = {fingerprint: cn for fingerprint, cn in old_members}
                target_cn = {fingerprint: cn for fingerprint, cn in new_members}
                detail = (f"matched={matched}/{len(old_members)} source fingerprints; "
                          f"missing on target={sum(missing.values())}; extra on target={sum(extra.values())}")
                if not standard_ca_bundle:
                    for heading, entries, names in (("missing", missing, source_cn),
                                                     ("extra", extra, target_cn)):
                        for fingerprint, count in sorted(entries.items()):
                            detail += (f"; {heading}: " + reporter.red(
                                f"CN={names.get(fingerprint) or '(unavailable)'} "
                                f"fingerprint={fingerprint}" + (f" x{count}" if count > 1 else "")))
                reporter.add("WARN" if standard_ca_bundle else "FAIL", label, detail)

    def compare_certificate(old_ref: str | None, new_ref: str | None, kind: str,
                            old_owner: str, new_owner: str) -> bool:
        """Return true for an intentionally unrenewed, long expired certificate."""
        label = f"{side.upper()} {kind} certificate {old_ref}"
        if not old_ref or old_ref == "none":
            return False
        if not new_ref or new_ref == "none":
            reporter.add("FAIL", label, "Certificate missing from target profile")
            return False
        if is_default_file(new_ref, "crt") and not is_default_file(old_ref, "crt"):
            old_inventory = inventories.get("cert", ({}, {}))[0]
            source_body = old_inventory.get(scoped_name(old_ref, old_owner))
            source_expiry = certificate_expiry(tmsh_property(source_body, "expiration-string")) if source_body else None
            if migrated_at and source_expiry and source_expiry < migrated_at - timedelta(days=30):
                reporter.add("WARN", label,
                             f"Target uses default.crt: source certificate expired "
                             f"{source_expiry:%d %B %Y %H:%M UTC}, more than 30 days before "
                             f"migration ({migrated_at:%d %B %Y}); replacement not expected")
                return True
            reason = ("migration date missing or unparseable" if not migrated_at else
                      "source certificate expiration unavailable" if not source_expiry else
                      "source certificate did not expire more than 30 days before migration")
            reporter.add("FAIL", label, f"Replacement certificate missing: target still uses default.crt ({reason})")
            return False
        if "cert" not in inventories:
            reporter.add("ERROR", label, "Certificate inventory unavailable")
            return False
        old_name, new_name = scoped_name(old_ref, old_owner), scoped_name(new_ref, new_owner)
        if kind == "server_ssl" and (old_name, new_name) not in visited_server_eku:
            visited_server_eku.add((old_name, new_name))
            reporter.add("WARN", f"{label} EKU", "Not exposed by validated tmsh output; unverified")
        if (old_name, new_name) in visited_certs:
            return False
        visited_certs.add((old_name, new_name))
        old_certs, new_certs = inventories["cert"]
        before, after = old_certs.get(old_name), new_certs.get(new_name)
        if before is None or after is None:
            reporter.add("FAIL", label, f"source={'present' if before else 'missing'} "
                         f"target={'present' if after else 'missing'}")
            return False
        old_props, new_props = certificate_properties(before), certificate_properties(after)
        old_cn, new_cn = certificate_cn(old_props["subject"]), certificate_cn(new_props["subject"])
        subject_status = ("WARN" if not old_cn or not new_cn else "FAIL" if old_cn != new_cn
                          else "PASS" if old_props["subject"] == new_props["subject"] else "WARN")
        reporter.add(subject_status, f"{label} subject",
                     f"source={old_props['subject']!r} target={new_props['subject']!r}")
        for field in ("issuer", "subject-alternative-name"):
            old_value, new_value = old_props[field], new_props[field]
            if field == "subject-alternative-name":
                reporter.compare_items(f"{label} {field}", san_items(old_value), san_items(new_value))
                continue
            status = ("PASS" if old_value == new_value else
                      "WARN" if field == "issuer" and allowed_issuer_upgrade(
                          old_value, new_value, issuer_upgrades) else "FAIL")
            reporter.add(status, f"{label} {field}",
                         f"source={old_value!r} target={new_value!r}")
        for field in ("key-type", "certificate-key-size", "certificate-key-curve-name"):
            old_value, new_value = old_props[field], new_props[field]
            if old_value != new_value:
                reporter.add("WARN" if old_value is None or new_value is None else "FAIL",
                             f"{label} {field}", f"source={old_value!r} target={new_value!r}")
        expires = certificate_expiry(new_props["expiration-string"])
        if expires is None:
            reporter.add("WARN", f"{label} expiration", "Target expiration-string missing or unparseable")
        elif expires <= datetime.now(timezone.utc):
            reporter.add("FAIL", f"{label} expiration", f"Target expired {expires:%d %b %Y %H:%M UTC}")
        elif old_cn and old_cn == new_cn and (old_props["issuer"] and
                                             (old_props["issuer"] == new_props["issuer"] or
                                              allowed_issuer_upgrade(old_props["issuer"], new_props["issuer"],
                                                                     issuer_upgrades))
                                             and Counter(san_items(old_props["subject-alternative-name"])) ==
                                             Counter(san_items(new_props["subject-alternative-name"]))):
            reporter.add("INFO", label, f"Valid replacement {new_name}; expires {expires:%d %b %Y %H:%M UTC}")
        reporter.add("WARN", f"{label} signature/key usage",
                     "Complete X.509 extensions not exposed by validated tmsh output; unverified")
        return False

    def compare_ssl(kind: str, old_ref: str, new_ref: str, old_owner: str, new_owner: str) -> None:
        old_name, new_name = scoped_name(old_ref, old_owner), scoped_name(new_ref, new_owner)
        label = f"{side.upper()} {kind} {old_name}"
        if (kind, old_name, new_name) in visited_profiles:
            return
        visited_profiles.add((kind, old_name, new_name))
        if kind not in inventories:
            reporter.add("ERROR", label, "SSL profile inventory unavailable")
            return
        old_profiles, new_profiles = inventories[kind]
        before, after = old_profiles.get(old_name), new_profiles.get(new_name)
        if before is None or after is None:
            reporter.add("FAIL", label, f"source={'present' if before else 'missing'} "
                         f"target={'present' if after else 'missing'}")
            return
        matching: list[str] = []
        for field in ("ciphers", "cipher-group", "authenticate", "authenticate-depth",
                      "server-name", "sni-default", "sni-require", "peer-cert-mode"):
            old_value, new_value = tmsh_property(before, field), tmsh_property(after, field)
            if old_value == new_value:
                matching.append(field)
            elif field == "ciphers" and old_value and new_value:
                # OpenSSL directives are order-sensitive: report individual
                # differences, and still fail if their order alone changes.
                reporter.compare_items(f"{label} {field}", old_value.split(":"),
                                       new_value.split(":"), ordered=True)
            else:
                reporter.add("FAIL", f"{label} {field}",
                             f"source={reporter.red(repr(old_value))} "
                             f"target={reporter.red(repr(new_value))}")
        if matching:
            reporter.add("PASS", f"{label} SSL attributes", f"Identical: {', '.join(matching)}")
        compare_ciphers(tmsh_property(before, "cipher-group"),
                        tmsh_property(after, "cipher-group"), old_name, new_name)
        for field in ("ca-file", "trusted-cert-authority"):
            compare_bundle(tmsh_property(before, field), tmsh_property(after, field), old_name, new_name)
        try:
            old_slots, new_slots = profile_cert_slots(before), profile_cert_slots(after)
        except ValueError as exc:
            reporter.add("ERROR", f"{label} cert-key-chain", str(exc))
            return
        if len(old_slots) != len(new_slots):
            reporter.add("FAIL", f"{label} cert-key-chain", f"source slots={len(old_slots)} target={len(new_slots)}")
        remaining = list(new_slots)

        def certificate_identity(slot: dict, owner: str, role: int) -> tuple | None:
            ref = slot["cert"]
            inventory = inventories.get("cert", ({}, {}))[role]
            body = inventory.get(scoped_name(ref, owner)) if ref and ref != "none" else None
            if body is None:
                return None
            props = certificate_properties(body)
            cn = certificate_cn(props["subject"])
            return (cn, props["issuer"], tuple(sorted(san_items(props["subject-alternative-name"])))) if cn else None

        for old_slot in old_slots:
            identity = certificate_identity(old_slot, old_name, 0)
            semantic = ([slot for slot in remaining
                         if certificate_identity(slot, new_name, 1) == identity]
                        if identity else [])
            by_name = [slot for slot in remaining if slot["slot"] == old_slot["slot"]]
            if len(semantic) == 1:
                new_slot = semantic[0]
            elif len(by_name) == 1:
                new_slot = by_name[0]
            elif len(remaining) == 1:
                new_slot = remaining[0]
            else:
                reporter.add("ERROR" if remaining else "FAIL", f"{label} slot {old_slot['slot']}",
                             f"No unique matching target cert-key-chain slot; candidates={len(remaining)}")
                continue
            remaining.remove(new_slot)
            matches = []
            for field in sorted(old_slot["attributes"].keys() | new_slot["attributes"].keys()):
                old_value, new_value = old_slot["attributes"].get(field), new_slot["attributes"].get(field)
                if old_value == new_value:
                    matches.append(field)
                else:
                    reporter.add("FAIL", f"{label} slot {old_slot['slot']} {field}",
                                 f"source={old_value!r} target={new_value!r}")
            if matches:
                reporter.add("PASS", f"{label} slot {old_slot['slot']} attributes",
                             f"Identical: {', '.join(matches)}")
            if compare_certificate(old_slot["cert"], new_slot["cert"], kind, old_name, new_name):
                # The external renewal process intentionally leaves this slot at
                # default.crt/default.key; dependent chain/key checks are irrelevant.
                continue
            compare_bundle(old_slot["chain"], new_slot["chain"], old_name, new_name)
            key_name = new_slot["key"]
            old_key = old_slot["key"]
            old_has_key = old_key not in (None, "none")
            new_has_key = key_name not in (None, "none")
            if old_has_key != new_has_key:
                reporter.add("FAIL", f"{label} key {old_slot['slot']}",
                             "Key missing on target" if old_has_key else "Unexpected target key")
                continue
            if not new_has_key:
                continue
            if is_default_file(key_name, "key") and old_key not in (None, "none") and not is_default_file(old_key, "key"):
                reporter.add("FAIL", f"{label} key {old_slot['slot']}",
                             "Replacement key missing: target still uses default.key")
                continue
            target_keys = inventories.get("key", ({}, {}))[1]
            present = scoped_name(key_name, new_name) in target_keys
            reporter.add("WARN" if present else "FAIL", f"{label} key {new_slot['slot']}",
                         "Key exists; target-only public-key match unverified" if present else "Key file missing on target")
        for extra in remaining:
            reporter.add("WARN", f"{label} target slot {extra['slot']}",
                         "No corresponding source cert-key-chain entry")
        parent_old = tmsh_property(before, "defaults-from")
        parent_new = tmsh_property(after, "defaults-from")
        if parent_old and parent_new and scoped_name(parent_old, old_name) != old_name:
            if scoped_name(parent_old, old_name) in old_profiles:
                compare_ssl(kind, parent_old, parent_new, old_name, new_name)
            else:
                reporter.add("WARN", f"{label} defaults-from",
                             "Parent SSL profile not collected; inherited certificate settings unverified")
        elif not old_slots and not new_slots:
            reporter.add("WARN", label, "No explicit cert/key slots; inherited or absent certificate unverified")

    for old_vip, new_vip in pairs:
        old_body, new_body = old_vips[old_vip], new_vips[new_vip]
        old_profiles = named_references(profile_lists[0].get(old_vip, old_body), "profiles")
        new_profiles = named_references(profile_lists[1].get(new_vip, new_body), "profiles")
        if not old_profiles and named_references(old_body, "profiles"):
            old_profiles = named_references(old_body, "profiles")
        if not new_profiles and named_references(new_body, "profiles"):
            new_profiles = named_references(new_body, "profiles")
        if len(old_profiles) != len(new_profiles):
            reporter.add("FAIL", f"{side.upper()} VIP {old_vip} SSL attachments",
                         f"source={old_profiles} target={new_profiles}")
        for old_ref, new_ref in paired_references(old_profiles, new_profiles, old_vip, new_vip):
            kind = next((candidate for candidate in ("client_ssl", "server_ssl")
                         if candidate in inventories and scoped_name(old_ref, old_vip) in inventories[candidate][0]), None)
            if kind:
                compare_ssl(kind, old_ref, new_ref, old_vip, new_vip)

    # Only HTTPS monitors in the pools attached to matched VIPs are in scope.
    old_pools, old_pool_error = application_data(source, "pool")
    new_pools, new_pool_error = application_data(target, "pool")
    if old_pool_error or new_pool_error or old_pools is None or new_pools is None:
        reporter.add("ERROR", f"{side.upper()} HTTPS monitor graph",
                     old_pool_error or new_pool_error or "Missing pool inventory")
        return
    if "https_monitor" not in inventories:
        return
    source_monitors, target_monitors = inventories["https_monitor"]
    visited_monitors: set[tuple[str, str]] = set()

    def compare_monitor(source_name: str, target_name: str) -> None:
        if (source_name, target_name) in visited_monitors:
            return
        visited_monitors.add((source_name, target_name))
        label = f"{side.upper()} HTTPS monitor {source_name}"
        src_body, dst_body = source_monitors.get(source_name), target_monitors.get(target_name)
        if src_body is None or dst_body is None:
            reporter.add("FAIL", label, f"source={'present' if src_body is not None else 'missing'} "
                         f"target={'present' if dst_body is not None else 'missing'}")
            return
        try:
            old_fields, new_fields = tmsh_fields(src_body), tmsh_fields(dst_body)
            for field in sorted(old_fields.keys() | new_fields.keys()):
                if field in {"cert", "key", "ca-file", "chain", "cert-key-chain", "ssl-profile"}:
                    continue
                old_value, new_value = old_fields.get(field), new_fields.get(field)
                if old_value != new_value:
                    reporter.add("FAIL", f"{label} {field}",
                                 f"source={old_value!r} target={new_value!r}")
        except ValueError as exc:
            reporter.add("ERROR", label, str(exc))
        expired_default = compare_certificate(tmsh_property(src_body, "cert"),
                                              tmsh_property(dst_body, "cert"),
                                              "https_monitor", source_name, target_name)
        compare_bundle(tmsh_property(src_body, "ca-file"), tmsh_property(dst_body, "ca-file"),
                       source_name, target_name)
        old_key, new_key = tmsh_property(src_body, "key"), tmsh_property(dst_body, "key")
        if old_key and old_key != "none" and not expired_default:
            if is_default_file(new_key, "key") and not is_default_file(old_key, "key"):
                reporter.add("FAIL", f"{label} key", "Replacement key missing: target still uses default.key")
            else:
                target_keys = inventories.get("key", ({}, {}))[1]
                present = bool(new_key and scoped_name(new_key, target_name) in target_keys)
                reporter.add("WARN" if present else "FAIL", f"{label} key",
                             "Key exists; target-only public-key match unverified" if present else
                             "Target monitor key missing")
        old_profile, new_profile = tmsh_property(src_body, "ssl-profile"), tmsh_property(dst_body, "ssl-profile")
        if old_profile and old_profile != "none":
            if new_profile and new_profile != "none":
                compare_ssl("server_ssl", old_profile, new_profile, source_name, target_name)
            else:
                reporter.add("FAIL", f"{label} ssl-profile", "SSL profile missing from target monitor")
        old_parent, new_parent = tmsh_property(src_body, "defaults-from"), tmsh_property(dst_body, "defaults-from")
        if old_parent and old_parent != "none" and scoped_name(old_parent, source_name) != source_name:
            if new_parent and new_parent != "none":
                old_parent_name = scoped_name(old_parent, source_name)
                if old_parent_name in source_monitors:
                    compare_monitor(old_parent_name, scoped_name(new_parent, target_name))
                else:
                    reporter.add("WARN", f"{label} defaults-from", "Inherited monitor not in HTTPS inventory")
            else:
                reporter.add("FAIL", f"{label} defaults-from", "Inherited monitor missing on target")

    def attached_monitors(expression: object, owner: str) -> list[str]:
        return [name for name in monitor_references(str(expression or ""), owner)
                if name in source_monitors or name in target_monitors]

    for old_vip, new_vip in pairs:
        old_pool = tmsh_property(old_vips[old_vip], "pool")
        new_pool = tmsh_property(new_vips[new_vip], "pool")
        if not old_pool or old_pool == "none":
            continue
        if not new_pool or new_pool == "none":
            reporter.add("FAIL", f"{side.upper()} VIP {old_vip} HTTPS monitors", "Target pool missing")
            continue
        src_pool_name, dst_pool_name = scoped_name(old_pool, old_vip), scoped_name(new_pool, new_vip)
        src_pool = old_pools.get(old_pool) or old_pools.get(src_pool_name)
        dst_pool = new_pools.get(new_pool) or new_pools.get(dst_pool_name)
        if not src_pool or not dst_pool:
            reporter.add("ERROR", f"{side.upper()} VIP {old_vip} HTTPS monitors", "Pool inventory missing")
            continue
        expressions = [(f"pool {src_pool_name}", src_pool["fields"].get("monitor"),
                        dst_pool["fields"].get("monitor"))]
        for identity, src_member in src_pool["members"].items():
            dst_member = dst_pool["members"].get(identity)
            if src_member["fields"].get("monitor") and dst_member:
                expressions.append((f"pool member {identity}", src_member["fields"]["monitor"],
                                    dst_member["fields"].get("monitor")))
        for location, src_expression, dst_expression in expressions:
            src_refs = [name for name in attached_monitors(src_expression, src_pool_name)
                        if name in source_monitors]
            dst_refs = [name for name in attached_monitors(dst_expression, dst_pool_name)
                        if name in target_monitors]
            for source_name in src_refs:
                if source_name in dst_refs:
                    target_name = source_name
                elif len(src_refs) == 1 and len(dst_refs) == 1:
                    target_name = dst_refs[0]
                    reporter.add("WARN", f"{side.upper()} HTTPS monitor {source_name}",
                                 f"Renamed to {target_name} on {location}")
                else:
                    reporter.add("FAIL", f"{side.upper()} HTTPS monitor {source_name}",
                                 f"No unique target HTTPS monitor on {location}; target={dst_refs}")
                    continue
                compare_monitor(source_name, target_name)


def compare_ntp_sync(reporter: Reporter, side: str, role: str, record: dict | None) -> None:
    ntp_record = record.get("privileged_ntp") if record else None
    if ntp_record is None:
        reporter.add("SKIP", f"{side.upper()} {role} NTP synchronization",
                     "Privileged ntpq output absent; set SSHPASSNET and collect new snapshots")
        return
    output, error = inventory_section(ntp_record, NTP_SYNC_COMMAND)
    if error:
        reporter.add("ERROR", f"{side.upper()} {role} NTP synchronization", error)
        return
    # ntpq marks the selected system peer with '*', immediately before its address.
    peers = re.findall(r"(?m)^\s*\*(\S+)\s+\S+\s+\d+\s+\S+\s+\S+\s+\d+\s+([0-7]{1,3})\s+", output or "")
    label = f"{side.upper()} {role} NTP synchronization"
    if peers:
        address, reach = peers[0]
        reporter.add("PASS" if int(reach, 8) else ("FAIL" if role == "target" else "WARN"),
                     label, f"selected peer={address} reach={reach}")
    elif re.search(r"(?m)^\s*[+ox#-]?\S+\s+\S+\s+\d+\s+\S+\s+", output or ""):
        reporter.add("FAIL" if role == "target" else "WARN", label, "ntpq listed peers but none is selected")
    elif re.search(r"(?i)no association|no peers", output or ""):
        reporter.add("FAIL" if role == "target" else "WARN", label, "ntpq reported no peers")
    else:
        reporter.add("ERROR", label, "Unrecognized ntpq output; inspect raw snapshot")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifest", type=Path, help="JSON from Export-F5Migration.ps1")
    ap.add_argument("--checks", default="permissions,basic,platform", help="permissions,basic,platform,network,routes,system,applications,references,certificates,all and !category exclusions")
    ap.add_argument("--filter", metavar="STATUSES", help="show only listed result labels, e.g. FAIL or FAIL,ERROR; summary still counts all")
    ap.add_argument("--nocolor", action="store_true", help="disable colored status labels")
    ap.add_argument("--member", choices=("a", "b"), help="check only this cluster member (default: both)")
    ap.add_argument("--issuer-upgrades", type=Path,
                    help="private JSON list of approved source_cn/target_cn issuer renewals")
    ap.add_argument("--hostname-suffix", help="private BIG-IP and F5OS hostname DNS suffix for comparison")
    ap.add_argument("--ntp-sync", action="store_true", help="compatibility option; NTP sync runs automatically for system checks when SSHPASSNET is set")
    ap.add_argument("--snapshot-dir", type=Path, help="write restricted raw SSH snapshots here")
    ap.add_argument("--from-snapshot", type=Path, help="compare previously saved snapshots offline")
    ap.add_argument("--collect-only", action="store_true")
    ap.add_argument("--f5os-account", choices=("regular", "privileged"), default="regular")
    ap.add_argument("--timeout", type=int, default=90, help="seconds per BIG-IP command or F5OS SSH session")
    ap.add_argument("--cli-ready-timeout", type=int, default=20, help="seconds to await a valid CLI response")
    ap.add_argument("--host-key-mode", choices=("yes", "accept-new", "legacy"), default="legacy",
                    help="legacy matches the working ksh collector (disables host-key verification); accept-new verifies known keys")
    args = ap.parse_args()
    if args.snapshot_dir and args.from_snapshot:
        ap.error("--snapshot-dir and --from-snapshot cannot be combined")
    if args.timeout < 10:
        ap.error("--timeout must be at least 10 seconds")
    if args.cli_ready_timeout < 1 or args.cli_ready_timeout > args.timeout:
        ap.error("--cli-ready-timeout must be between 1 and --timeout")
    checks = parse_checks(args.checks)
    hostname_suffix = args.hostname_suffix or os.environ.get("F5_HOSTNAME_SUFFIX")
    if not hostname_suffix:
        suffix_file = Path(__file__).resolve().parent / ".private" / "hostname-suffix.txt"
        hostname_suffix = suffix_file.read_text(encoding="utf-8").strip() if suffix_file.is_file() else ""
    if "basic" in checks and (not hostname_suffix or not re.fullmatch(r"\.[A-Za-z0-9.-]+", hostname_suffix)):
        ap.error("Basic hostname check requires --hostname-suffix, F5_HOSTNAME_SUFFIX, or a private hostname-suffix.txt")
    issuer_map_path = args.issuer_upgrades
    if issuer_map_path is None:
        default_map_path = Path(__file__).resolve().parent / ".private" / "issuer-upgrades.json"
        issuer_map_path = default_map_path if default_map_path.is_file() else None
    issuer_upgrades = load_issuer_upgrades(issuer_map_path) if "certificates" in checks else set()
    if checks != {"permissions"} and not args.from_snapshot and not args.snapshot_dir:
        ap.error("A live run requires --snapshot-dir for raw CLI evidence")
    try:
        status_filter = parse_status_filter(args.filter)
    except ValueError as exc:
        ap.error(str(exc))
    manifest = load_manifest(args.manifest)
    color = (not args.nocolor and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
             and "NO_COLOR" not in os.environ)
    reporter = Reporter(status_filter=status_filter, color=color)
    if "certificates" in checks and issuer_map_path is None:
        reporter.add("WARN", "Issuer renewal mapping",
                     "Private issuer upgrade map missing; any changed issuer will fail")
    members = (args.member,) if args.member else ("a", "b")
    package = manifest.get("package_details") or {}
    parsed_date = parse_migration_date(manifest.get("migration_date"))
    date_label = (parsed_date.strftime("%d-%B-%Y") if parsed_date else manifest.get("migration_date"))
    metadata = (("Migration package", manifest.get("migration_package")),
                ("Migration date", date_label),
                ("F5 engineer", package.get("migration_engineer")),
                ("PM", package.get("project_manager")),
                ("TL", package.get("technical_lead")),
                ("ACI engineer", package.get("aci_engineer")))
    reporter.add("INFO", "Migration", "\t".join(
        f"{name}: {re.sub(r'\s+', ' ', str(value)).strip() if value not in (None, '') else '(missing)'}"
        for name, value in metadata), force=True, inline=True)
    if "permissions" in checks:
        check_permissions(reporter, manifest, args.host_key_mode,
                          offline=bool(args.from_snapshot), check_system="system" in checks,
                          check_bigip=True, members=members)

    target_records: dict[str, dict | None] = {}
    for side in members:
        device = manifest["devices"][side]
        roles = (["source", "target"] if checks & {"basic", "network", "routes", "system", "applications", "references", "certificates"} else []) + (["rseries_host"] if checks & {"platform", "network"} else [])
        collected: dict[str, dict | None] = {}
        for role in roles:
            expected = device[role]
            host = expected["ssh_host"]
            cli = "f5os" if role == "rseries_host" else "bigip"
            account = args.f5os_account if cli == "f5os" else "regular"
            if cli == "bigip":
                commands = ["show sys version", "list sys global-settings hostname",
                            "list sys management-ip", "list sys management-route default"]
                if role == "target" and "basic" in checks:
                    commands += HA_COMMANDS
                if "network" in checks:
                    commands += list(NETWORK_COMMANDS.values())
                elif checks & {"applications", "references", "certificates"}:
                    commands.append(NETWORK_COMMANDS["vlan"])
                if "routes" in checks:
                    commands += list(ROUTE_COMMANDS.values())
                if "system" in checks:
                    commands += list(SYSTEM_COMMANDS.values())
                if checks & {"applications", "references", "certificates"}:
                    commands += [*APPLICATION_COMMANDS.values(), POOL_MEMBER_PORT_COMMAND]
                if "references" in checks:
                    commands += list(REFERENCE_COMMANDS.values())
                if checks & {"references", "certificates"}:
                    commands += list(CERTIFICATE_COMMANDS.values())
                if "certificates" in checks and "references" not in checks:
                    commands += [REFERENCE_COMMANDS["cipher_group"], REFERENCE_COMMANDS["cipher_rule"]]
            else:
                commands = ["show system version | nomore", "show system state hostname",
                            "show system mgmt-ip", "show tenants | nomore", "show fips | nomore"]
                if "platform" in checks:
                    commands.append("show system licensing | nomore")
            label = f"{side.upper()} {role} {host}"
            print(f"\nCollecting {label} ({account})...", flush=True)
            try:
                if args.from_snapshot:
                    record = read_snapshot(snapshot_path(args.from_snapshot, side, role), host)
                else:
                    record = collect_ssh(host, cli, commands, account, args.timeout,
                                         args.cli_ready_timeout, args.host_key_mode)
                    if cli == "bigip" and "system" in checks and os.environ.get("SSHPASSNET"):
                        record["privileged_ntp"] = collect_privileged_ntp(host, args.host_key_mode)
                    if args.snapshot_dir:
                        save_snapshot(snapshot_path(args.snapshot_dir, side, role), record)
                if record.get("error"):
                    reporter.add("ERROR", label, record["error"])
                elif args.collect_only:
                    reporter.add("INFO", label, "Collected")
                collected[role] = record
            except (OSError, ValueError, RuntimeError) as exc:
                reporter.add("ERROR", label, str(exc))
                collected[role] = None

        if "basic" in checks:
            target_records[side] = collected.get("target")
        if args.collect_only:
            continue
        if "basic" in checks:
            for role in ("source", "target"):
                record = collected.get(role)
                if record is not None and not record.get("error"):
                    compare_bigip(reporter, side, role, device[role], bigip_data(record), hostname_suffix)
        if "platform" in checks:
            record = collected.get("rseries_host")
            if record is not None and not record.get("error"):
                compare_platform(reporter, side, device, f5os_data(
                    record, device["target"]["tenant_name_candidates"]), hostname_suffix)
        if "network" in checks:
            compare_network(reporter, side, collected.get("source"), collected.get("target"),
                            collected.get("rseries_host"), device["target"]["tenant_name_candidates"])
        if "routes" in checks:
            compare_routes(reporter, side, collected.get("source"), collected.get("target"),
                           device["target"]["management_gateway"])
        if "system" in checks:
            compare_system(reporter, side, collected.get("source"), collected.get("target"))
            for role in ("source", "target"):
                compare_ntp_sync(reporter, side, role, collected.get(role))
        if "applications" in checks:
            compare_applications(reporter, side, collected.get("source"), collected.get("target"))
        if "references" in checks:
            compare_references(reporter, side, collected.get("source"), collected.get("target"))
        if "certificates" in checks:
            compare_certificates(reporter, side, collected.get("source"), collected.get("target"),
                                 manifest.get("migration_date"), issuer_upgrades)
    if "basic" in checks and not args.collect_only:
        compare_target_ha(reporter, manifest, target_records, hostname_suffix, members)
    return reporter.finish()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
