#!/usr/bin/env python3
"""Read-only F5 migration validator (manifest schema 2).

`basic`, `platform`, `network`, `routes`, `system`, and `applications` are implemented. BIG-IP login lands in tmsh;
F5OS login lands in the appliance CLI. One interactive SSH session is used
per endpoint. Supply --snapshot-dir on the first live run so unexpected CLI
output can be checked safely offline. Ctrl+C interrupts the current SSH
session and continues; Ctrl+\\ terminates the process. Permission probes use
short direct SSH calls; NTP synchronization uses the privileged BIG-IP login
when SSHPASSNET is set.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import tty


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
BIGIP_PROMPT = re.compile(r"(?im)^[^\n]{0,320}\(tmos\)#[ \t\n]*\Z")
DISPLAY_CONFIRM = re.compile(r"(?i)Display all\s+\d+\s+items\?\s*\(y/n\)[ \t\n]*\Z")
DISPLAY_PROMPT = re.compile(r"(?i)Display all\s+\d+\s+items\?")
DISPLAY_DECLINED = re.compile(r"(?i)Display all\s+\d+\s+items\?\s*\(y/n\)\s*n\b")


def parse_checks(spec: str) -> set[str]:
    selected: set[str] = set()
    known = {"basic", "platform", "network", "routes", "system", "applications"}
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
            raise ValueError(f"Unsupported check category: {token!r}; available: basic,platform,network,routes,system,applications")
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
    """F5OS licensing displays a registration key; omit it from snapshots."""
    return re.sub(r"(?im)^(\s*Registration key\s+)\S+", r"\g<1>[REDACTED]", raw)


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
                      *, offline: bool, check_system: bool, check_bigip: bool) -> None:
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
    for side in ("a", "b"):
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


def collect_ssh(host: str, cli: str, commands: list[str], account: str,
                timeout: int, ready_timeout: int, host_key_mode: str) -> dict:
    if not shutil.which("sshpass") or not shutil.which("ssh"):
        raise RuntimeError("ssh and sshpass are required on the jump host")
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
    exit_cmd = "quit" if cli == "bigip" else "exit"
    # The CLI may discard keystrokes sent while the login banner is still
    # loading. Retry a read-only probe until its *output* proves readiness.
    ready_pattern = BIGIP_READY if cli == "bigip" else F5OS_READY
    collected = bytearray()
    sections: dict[str, str] = {}
    confirmed_display_prompts: dict[str, int] = {}
    error = None
    proc = None
    input_master = None
    input_slave = None
    try:
        if cli == "bigip":
            # A piped local SSH stdin causes some tmsh installations to
            # default the display-threshold question to 'n' immediately.
            # Present a real local terminal to SSH as in a manual session.
            input_master, input_slave = pty.openpty()
            tty.setraw(input_slave)
        proc = subprocess.Popen(argv, stdin=input_slave if input_slave is not None else subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=ssh_env)
        if input_slave is not None:
            os.close(input_slave)
            input_slave = None
        assert proc.stdout

        def send_input(value: str) -> None:
            if input_master is not None:
                os.write(input_master, value.encode())
            else:
                assert proc and proc.stdin
                proc.stdin.write(value.encode())
                proc.stdin.flush()

        fd = proc.stdout.fileno()
        started = time.monotonic()
        deadline = started + timeout
        ready_deadline = started + min(ready_timeout, timeout)
        next_probe = started
        ready = False
        eof = False
        next_command = 1
        segment_start = 0
        last_display_response = 0
        exit_sent = False
        try:
            while time.monotonic() < deadline:
                now = time.monotonic()
                if not ready and now >= next_probe and proc.poll() is None:
                    try:
                        send_input(commands[0] + "\n")
                    except (BrokenPipeError, OSError):
                        break
                    next_probe = now + 3
                readable, _, _ = select.select([fd], [], [], min(0.5, max(0, deadline - now)))
                if readable:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        eof = True
                        break
                    collected.extend(chunk)
                    cleaned = clean_transcript(collected.decode("utf-8", "replace"))
                    if not ready and ready_pattern.search(cleaned):
                        ready = True
                        if cli == "f5os":
                            # The F5OS collector uses the established nomore
                            # flow; BIG-IP waits for each tmsh prompt below.
                            try:
                                send_input("\n".join([*commands[1:], exit_cmd, ""]))
                                assert proc.stdin
                                proc.stdin.close()
                            except (BrokenPipeError, OSError):
                                break
                    if ready and cli == "bigip" and not exit_sent:
                        pending_display = DISPLAY_CONFIRM.search(cleaned[segment_start:])
                        if pending_display and segment_start + pending_display.end() > last_display_response:
                            # tmsh asks for confirmation before printing large
                            # one-line inventories. A newline alone may decline.
                            try:
                                send_input("y\n")
                                command = commands[next_command - 1]
                                confirmed_display_prompts[command] = confirmed_display_prompts.get(command, 0) + 1
                                last_display_response = segment_start + pending_display.end()
                            except (BrokenPipeError, OSError):
                                break
                        prompt = BIGIP_PROMPT.search(cleaned)
                        if prompt and prompt.end() > segment_start:
                            sections[commands[next_command - 1]] = cleaned[segment_start:prompt.start()].strip()
                            try:
                                if next_command < len(commands):
                                    send_input(commands[next_command] + "\n")
                                    next_command += 1
                                    segment_start = len(cleaned)
                                else:
                                    send_input(exit_cmd + "\n")
                                    exit_sent = True
                            except (BrokenPipeError, OSError):
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
        if input_master is not None:
            os.close(input_master)
        if input_slave is not None:
            os.close(input_slave)
        ssh_env.pop("SSHPASS", None)
        password = ""  # Never save credentials to the snapshot.
    return {"host": host, "cli": cli, "account": account, "commands": commands,
            "returncode": proc.returncode, "error": error, "raw": raw,
            "sections": sections if cli == "bigip" else split_transcript(raw, commands),
            "confirmed_display_prompts": confirmed_display_prompts}


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
NTP_SYNC_COMMAND = 'bash -c "ntpq -np"'


def tmsh_objects(output: str, kind: str, *, allow_identical_duplicates: bool = False) -> dict[str, str]:
    """Extract complete tmsh objects, including multiline nested blocks."""
    objects: dict[str, str] = {}
    component = kind if " " in kind else "net " + kind
    header = re.compile(r"(?m)^\s*" + re.escape(component).replace(r"\ ", r"\s+")
                        + r"\s+(\S+)\s*\{")
    for match in header.finditer(output):
        depth = 1
        start = match.end()
        end = start
        while end < len(output) and depth:
            if output[end] == "{":
                depth += 1
            elif output[end] == "}":
                depth -= 1
            end += 1
        if depth:
            raise ValueError(f"Incomplete net {kind} object {match.group(1)!r}")
        name = match.group(1)
        if name in objects:
            if allow_identical_duplicates and tmsh_fields(objects[name]) == tmsh_fields(output[start:end - 1]):
                continue  # A legacy snapshot may contain both the default query and the full listing.
            raise ValueError(f"Repeated net {kind} object {name!r}")
        objects[name] = output[start:end - 1]
    return objects


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
    if count > confirmed or re.search(r"(?i)--More--|\(END\)", output):
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
        if not (command in (*ROUTE_COMMANDS.values(), *APPLICATION_COMMANDS.values()) and
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
            fields = tmsh_fields(body)
            entry: dict = {"fields": fields}
            if kind == "virtual":
                entry["destination"] = fields.get("destination")
                entry["protocol"] = fields.get("ip-protocol", "tcp")
                if not entry["destination"]:
                    raise ValueError(f"ltm virtual {name}: destination missing")
            else:
                member_block = tmsh_block(body, "members")
                members: dict[str, dict] = {}
                for member, member_body in tmsh_objects_from_block(member_block or ""):
                    properties = tmsh_fields(member_body)
                    # The node name can change; an explicit address and service port
                    # identify the actual backend more reliably.
                    port = member.rsplit(":", 1)[-1] if ":" in member else ""
                    address = properties.get("address") or member.rsplit(":", 1)[0]
                    identity = f"{address}:{port}"
                    if identity in members:
                        raise ValueError(f"ltm pool {name}: repeated member endpoint {identity}")
                    members[identity] = {"name": member, "fields": properties}
                if member_block is None and fields.get("members") not in (None, "none"):
                    raise ValueError(f"ltm pool {name}: unrecognized members value")
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
    depth = 1
    for pos in range(start, len(body)):
        if body[pos] == "{":
            depth += 1
        elif body[pos] == "}":
            depth -= 1
            if not depth:
                return body[start:pos]
    raise ValueError(f"Incomplete {property_name} block")


def tmsh_property(body: str, name: str) -> str | None:
    match = re.search(r"(?<![\w-])" + re.escape(name) + r"\s+(?!\{)([^\s{}]+)", body)
    return match.group(1).strip('"') if match else None


def tmsh_fields(body: str) -> dict[str, str | tuple[str, ...]]:
    """Read every top-level property, preserving nested properties as tokens."""
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[{}]|[^\s{}"]+', body)
    fields: dict[str, str | tuple[str, ...]] = {}
    index = 0
    while index < len(tokens):
        key = tokens[index]
        if key in ("{", "}") or index + 1 >= len(tokens):
            raise ValueError(f"Malformed tmsh property near {key!r}")
        index += 1
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
    """Parse interface member names and their nested properties."""
    members: list[tuple[str, str]] = []
    offset = 0
    while match := re.search(r"([^\s{}]+)\s*\{", block[offset:]):
        body_start = offset + match.end()
        depth = 1
        pos = body_start
        while pos < len(block) and depth:
            if block[pos] == "{":
                depth += 1
            elif block[pos] == "}":
                depth -= 1
            pos += 1
        if depth:
            raise ValueError(f"Incomplete interface member {match.group(1)!r}")
        members.append((match.group(1), block[body_start:pos - 1]))
        offset = pos
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

    def add(self, status: str, label: str, detail: str) -> None:
        self.results.append((status, label, detail))
        if self.status_filter is None or status in self.status_filter:
            token = f"[{status:<5}]"
            if self.color:
                token = f"{STATUS_COLORS[status]}{token}\x1b[0m"
            print(f"{token} {label:<45} {detail}")
            self.displayed += 1

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
                  observed: dict) -> None:
    prefix = f"{side.upper()} {role} BIG-IP"
    reporter.compare(f"{prefix} hostname", expected["expected_hostname"],
                     observed.get("hostname"), observed.get("hostname_error"),
                     casefold=True, hostname_suffix=".net.global")
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


def compare_platform(reporter: Reporter, side: str, expected: dict, observed: dict) -> None:
    prefix = f"{side.upper()} F5OS"
    host = expected["rseries_host"]
    target = expected["target"]
    reporter.compare(f"{prefix} host hostname", host["expected_hostname"],
                     observed.get("hostname"), observed.get("hostname_error"), casefold=True)
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
            for field in ("destination", "ip-protocol", "source", "mask", "pool", "disabled", "enabled"):
                before, after = src_fields.get(field), dst_fields.get(field)
                if field == "pool":
                    before = object_path(str(before)) if before not in (None, "none") else before
                    after = object_path(str(after)) if after not in (None, "none") else after
                if before != after:
                    reporter.add("FAIL", f"{label} {field}", f"source={before!r} target={after!r}")
            for field in ("profiles", "rules", "persist", "fallback-persistence",
                          "source-address-translation", "vlans", "vlans-enabled"):
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
    ap.add_argument("--checks", default="basic,platform", help="basic,platform,network,routes,system,applications,all and !category exclusions")
    ap.add_argument("--filter", metavar="STATUSES", help="show only listed result labels, e.g. FAIL or FAIL,ERROR; summary still counts all")
    ap.add_argument("--nocolor", action="store_true", help="disable colored status labels")
    ap.add_argument("--ntp-sync", action="store_true", help="compatibility option; NTP sync runs automatically for system checks when SSHPASSNET is set")
    ap.add_argument("--snapshot-dir", type=Path, help="write restricted raw SSH snapshots here")
    ap.add_argument("--from-snapshot", type=Path, help="compare previously saved snapshots offline")
    ap.add_argument("--collect-only", action="store_true")
    ap.add_argument("--f5os-account", choices=("regular", "privileged"), default="regular")
    ap.add_argument("--timeout", type=int, default=90, help="seconds per SSH session")
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
    if not args.from_snapshot and not args.snapshot_dir:
        ap.error("A live run requires --snapshot-dir for raw CLI evidence")
    checks = parse_checks(args.checks)
    try:
        status_filter = parse_status_filter(args.filter)
    except ValueError as exc:
        ap.error(str(exc))
    manifest = load_manifest(args.manifest)
    color = (not args.nocolor and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
             and "NO_COLOR" not in os.environ)
    reporter = Reporter(status_filter=status_filter, color=color)
    print(f"Migration {manifest['migration_package']} | checks={','.join(sorted(checks))} | read-only")
    check_permissions(reporter, manifest, args.host_key_mode,
                      offline=bool(args.from_snapshot), check_system="system" in checks,
                      check_bigip=bool(checks & {"basic", "network", "routes", "system", "applications"}))

    for side in ("a", "b"):
        device = manifest["devices"][side]
        roles = (["source", "target"] if checks & {"basic", "network", "routes", "system", "applications"} else []) + (["rseries_host"] if checks & {"platform", "network"} else [])
        collected: dict[str, dict | None] = {}
        for role in roles:
            expected = device[role]
            host = expected["ssh_host"]
            cli = "f5os" if role == "rseries_host" else "bigip"
            account = args.f5os_account if cli == "f5os" else "regular"
            if cli == "bigip":
                commands = ["show sys version", "list sys global-settings hostname",
                            "list sys management-ip", "list sys management-route default"]
                if "network" in checks:
                    commands += list(NETWORK_COMMANDS.values())
                if "routes" in checks:
                    commands += list(ROUTE_COMMANDS.values())
                if "system" in checks:
                    commands += list(SYSTEM_COMMANDS.values())
                if "applications" in checks:
                    commands += list(APPLICATION_COMMANDS.values())
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

        if args.collect_only:
            continue
        if "basic" in checks:
            for role in ("source", "target"):
                record = collected.get(role)
                if record is not None and not record.get("error"):
                    compare_bigip(reporter, side, role, device[role], bigip_data(record))
        if "platform" in checks:
            record = collected.get("rseries_host")
            if record is not None and not record.get("error"):
                compare_platform(reporter, side, device, f5os_data(
                    record, device["target"]["tenant_name_candidates"]))
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
    return reporter.finish()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
