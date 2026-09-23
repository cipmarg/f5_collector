#!/usr/bin/env python3
"""Read-only F5 migration validator (manifest schema 2).

`basic`, `platform`, and `network` are implemented. BIG-IP login lands in tmsh;
F5OS login lands in the appliance CLI. One interactive SSH session is used
per endpoint. Supply --snapshot-dir on the first live run so unexpected CLI
output can be checked safely offline. Ctrl+C interrupts the current SSH
session and continues; Ctrl+\\ terminates the process.
"""

from __future__ import annotations

import argparse
import getpass
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
SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
SAFE_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")
ERROR_TEXT = re.compile(r"(?im)^\s*(?:syntax error\b|%\s*(?:error|invalid|no entries)\b|error:|unknown command\b|permission denied\b)")
VERSION_TEXT = re.compile(r"\b(\d+(?:\.\d+){2,4})\s+([0-9]+(?:\.[0-9]+){2,4})\b")
F5OS_READY = re.compile(r"(?m)^\s*system\s+version\s+os-version\s+\S+")
BIGIP_READY = re.compile(r"(?im)^\s*Version\s+\d+(?:\.\d+){2,4}\s*$")


def parse_checks(spec: str) -> set[str]:
    selected: set[str] = set()
    known = {"basic", "platform", "network"}
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
            raise ValueError(f"Unsupported check category: {token!r}; available: basic,platform,network")
    if not selected:
        raise ValueError("No checks selected")
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
        try:
            while time.monotonic() < deadline:
                now = time.monotonic()
                if not ready and now >= next_probe and proc.poll() is None:
                    try:
                        proc.stdin.write((commands[0] + "\n").encode())
                        proc.stdin.flush()
                    except BrokenPipeError:
                        break
                    next_probe = now + 1
                readable, _, _ = select.select([fd], [], [], min(0.5, max(0, deadline - now)))
                if readable:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        eof = True
                        break
                    collected.extend(chunk)
                    if not ready and ready_pattern.search(clean_transcript(collected.decode("utf-8", "replace"))):
                        ready = True
                        try:
                            proc.stdin.write(("\n".join([*commands[1:], exit_cmd, ""])).encode())
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
        raw = collected.decode("utf-8", "replace")
        if not error and proc.returncode:
            diagnostic = next((line.strip() for line in reversed(clean_transcript(raw).splitlines())
                               if re.search(r"permission denied|host key|resolve hostname|connection refused|no route|timed out", line, re.I)), "")
            error = f"SSH exited {proc.returncode}" + (f": {diagnostic[:180]}" if diagnostic else "; inspect raw snapshot")
    finally:
        ssh_env.pop("SSHPASS", None)
        password = ""  # Never save credentials to the snapshot.
    return {"host": host, "cli": cli, "account": account, "commands": commands,
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


def tmsh_objects(output: str, kind: str) -> dict[str, str]:
    """Extract complete tmsh objects, including multiline nested blocks."""
    objects: dict[str, str] = {}
    header = re.compile(r"(?m)^\s*net\s+" + re.escape(kind) + r"\s+(\S+)\s*\{")
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
            raise ValueError(f"Repeated net {kind} object {name!r}")
        objects[name] = output[start:end - 1]
    return objects


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
    if re.search(r"(?i)Display all(?: \d+)? items\?|--More--|\(END\)", raw):
        return None, f"{command} stopped at a tmsh display prompt; inventory may be incomplete"
    try:
        objects = tmsh_objects(output or "", kind)
        if not objects and raw and raw != output:
            objects = tmsh_objects(raw, kind)
        if not objects:
            return None, f"No net {kind} objects found; inspect raw snapshot for pager or CLI errors"
        result: dict[str, dict] = {}
        for name, body in objects.items():
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
                result[name] = {"tag": tag, "interfaces": sorted(members)}
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
                result[name] = {"address": address, "vlan": vlan, "traffic_group": group,
                                "floating": not group.rsplit("/", 1)[-1].lower() == "traffic-group-local-only"}
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


def f5os_data(record: dict | None, candidates: list[str]) -> dict:
    values: dict = {}
    output, error = section(record, "show system version | nomore")
    if error:
        values["product_error"] = error
    else:
        match = re.search(r"(?im)^\s*system\s+version\s+product\s+(\S+)", output)
        values["product"] = match.group(1) if match else None
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
    def __init__(self) -> None:
        self.results: list[tuple[str, str, str]] = []

    def add(self, status: str, label: str, detail: str) -> None:
        self.results.append((status, label, detail))
        print(f"[{status:<5}] {label:<45} {detail}")

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
                  for status in ("PASS", "FAIL", "WARN", "ERROR", "SKIP", "INFO")}
        print("\n" + " ".join(f"{key}={value}" for key, value in counts.items()))
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
    reporter.add("INFO" if observed.get("product") else "SKIP", f"{prefix} host product",
                 f"reported={observed['product']!r} expected model={host['model']!r}"
                 if observed.get("product") else observed.get("product_error") or "Product missing in F5OS version output")
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


def compare_network(reporter: Reporter, side: str, source: dict | None,
                    target: dict | None) -> None:
    """Show source-to-target differences; a migration mapping is needed to adjudicate them."""
    for kind in ("vlan", "self"):
        label = f"{side.upper()} {kind.upper()} network inventory"
        src, src_error = network_data(source, kind)
        dst, dst_error = network_data(target, kind)
        if src_error or dst_error:
            for role, error in (("source", src_error), ("target", dst_error)):
                if error:
                    reporter.add("ERROR", f"{label} {role}", error)
            continue
        assert src is not None and dst is not None
        differences = 0
        for name in sorted(src.keys() | dst.keys()):
            if name not in dst:
                reporter.add("WARN", f"{side.upper()} {kind} {name}", "Present on source; absent from target")
                differences += 1
            elif name not in src:
                reporter.add("WARN", f"{side.upper()} {kind} {name}", "Present on target; absent from source")
                differences += 1
            else:
                fields = ("tag", "interfaces") if kind == "vlan" else (
                    "address", "vlan", "traffic_group", "floating")
                for field in fields:
                    if src[name][field] != dst[name][field]:
                        reporter.add("WARN", f"{side.upper()} {kind} {name} {field}",
                                     f"source={src[name][field]!r} target={dst[name][field]!r}")
                        differences += 1
        reporter.add("PASS" if not differences else "INFO", label,
                     f"source={len(src)} target={len(dst)} differences={differences}; "
                     + ("matched" if not differences else "review migration mapping for WARN entries"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifest", type=Path, help="JSON from Export-F5Migration.ps1")
    ap.add_argument("--checks", default="basic,platform", help="basic,platform,network,all,!basic,!platform,!network")
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
    manifest = load_manifest(args.manifest)
    reporter = Reporter()
    print(f"Migration {manifest['migration_package']} | checks={','.join(sorted(checks))} | read-only")

    for side in ("a", "b"):
        device = manifest["devices"][side]
        roles = (["source", "target"] if checks & {"basic", "network"} else []) + (["rseries_host"] if "platform" in checks else [])
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
            else:
                commands = ["show system version | nomore", "show system state hostname",
                            "show system mgmt-ip", "show tenants | nomore", "show fips | nomore"]
            label = f"{side.upper()} {role} {host}"
            print(f"\nCollecting {label} ({account})...", flush=True)
            try:
                if args.from_snapshot:
                    record = read_snapshot(snapshot_path(args.from_snapshot, side, role), host)
                else:
                    record = collect_ssh(host, cli, commands, account, args.timeout,
                                         args.cli_ready_timeout, args.host_key_mode)
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
            compare_network(reporter, side, collected.get("source"), collected.get("target"))
    return reporter.finish()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
