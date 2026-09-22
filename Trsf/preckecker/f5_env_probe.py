#!/usr/bin/env python3
"""
f5_env_probe.py

Read-only environment probe for the F5 migration validation framework.

Checks the jump host for:
  - Python/runtime details
  - required local commands
  - authentication environment variables
  - useful optional Python modules

Optionally checks one or more F5 devices for:
  - SSH access with the regular account ($USER / $SSHPASS)
  - SSH access with the privileged account (${USER}_net / $SSHPASSNET)
  - ability to retrieve BIG-IP software version
  - whether the regular account can enter bash (it should NOT)
  - whether the privileged account can enter bash

No configuration changes are made.
Passwords are never printed.
"""

import argparse
import importlib.util
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass


TIMEOUT = 15


@dataclass
class Result:
    status: str
    check: str
    detail: str = ""


RESULTS = []


def add(status, check, detail=""):
    RESULTS.append(Result(status, check, detail))
    suffix = f" - {detail}" if detail else ""
    print(f"[{status:<5}] {check}{suffix}")


def run(cmd, *, env=None, timeout=TIMEOUT):
    try:
        p = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as exc:
        return 125, "", str(exc)


def first_line(text):
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def command_version(path, name):
    candidates = {
        "ssh": [[path, "-V"]],
        "scp": [[path, "-V"]],
        "sshpass": [[path, "-V"]],
        "awk": [[path, "--version"], [path, "-W", "version"]],
        "ksh": [[path, "--version"]],
        "bash": [[path, "--version"]],
        "openssl": [[path, "version"]],
        "sed": [[path, "--version"]],
        "grep": [[path, "--version"]],
        "jq": [[path, "--version"]],
        "timeout": [[path, "--version"]],
    }

    for cmd in candidates.get(name, []):
        rc, out, err = run(cmd, timeout=5)
        text = first_line(out) or first_line(err)
        if text:
            return text
    return "present"


def local_probe():
    print("\n=== Jump host ===")

    add("INFO", "Host", platform.node() or "(unknown)")
    add("INFO", "OS", f"{platform.system()} {platform.release()} ({platform.machine()})")
    add("INFO", "Python executable", sys.executable)
    add("INFO", "Python version", platform.python_version())

    if sys.version_info >= (3, 10):
        add("PASS", "Python suitability", "Python >= 3.10")
    else:
        add("FAIL", "Python suitability", "Python 3.10+ recommended")

    shell = os.environ.get("SHELL", "")
    add("INFO", "Login shell", shell or "(not set)")

    print("\n=== Local commands ===")
    required = ["ssh", "sshpass", "scp", "awk", "openssl", "grep", "sed"]
    optional = ["ksh", "bash", "jq", "timeout"]

    for name in required:
        path = shutil.which(name)
        if path:
            add("PASS", name, f"{path} | {command_version(path, name)}")
        else:
            add("FAIL", name, "not found in PATH")

    for name in optional:
        path = shutil.which(name)
        if path:
            add("INFO", name, f"{path} | {command_version(path, name)}")
        else:
            add("INFO", name, "not found (not required)")

    print("\n=== Authentication variables ===")
    user = os.environ.get("USER", "")
    if user:
        add("PASS", "USER", user)
        add("INFO", "Privileged username", f"{user}_net")
    else:
        add("FAIL", "USER", "not set")

    if os.environ.get("SSHPASS"):
        add("PASS", "SSHPASS", "set")
    else:
        add("WARN", "SSHPASS", "not set; regular-account SSH probe will be skipped")

    if os.environ.get("SSHPASSNET"):
        add("PASS", "SSHPASSNET", "set")
    else:
        add("WARN", "SSHPASSNET", "not set; privileged-account SSH probe will be skipped")

    print("\n=== Python modules ===")
    # Standard-library modules the validator will rely on.
    stdlib = ["argparse", "json", "csv", "subprocess", "re", "ipaddress",
              "datetime", "hashlib", "ssl"]
    for module in stdlib:
        try:
            __import__(module)
            add("PASS", module, "standard library")
        except Exception as exc:
            add("FAIL", module, str(exc))

    # Useful if already installed, but the design does not require them.
    optional_modules = ["cryptography", "paramiko", "yaml", "requests", "openpyxl"]
    for module in optional_modules:
        spec = importlib.util.find_spec(module)
        if spec:
            try:
                mod = __import__(module)
                ver = getattr(mod, "__version__", "")
                add("INFO", module, f"available{(' v' + ver) if ver else ''}")
            except Exception as exc:
                add("WARN", module, f"found but import failed: {exc}")
        else:
            add("INFO", module, "not installed (not required)")


def ssh_base(host, user):
    return [
        shutil.which("sshpass") or "sshpass",
        "-e",
        shutil.which("ssh") or "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=8",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        "-o", "LogLevel=ERROR",
        f"{user}@{host}",
    ]


def ssh_exec(host, user, password, remote_command):
    env = os.environ.copy()

    # sshpass -e only reads SSHPASS.  For the privileged account we map
    # SSHPASSNET into SSHPASS in the child process only.
    env["SSHPASS"] = password

    cmd = ssh_base(host, user) + [remote_command]
    return run(cmd, env=env)


def retrieve_version(host, user, password, privileged=False):
    # A regular F5 account may land directly in tmsh, whereas the privileged
    # account may have bash. Try both harmless read-only forms.
    # Both the regular and privileged accounts land in tmsh.
    # Prefer native tmsh syntax. If we ever need to execute a bash-side
    # tmsh command, explicitly enter bash with bash -c.
    commands = [
        "show sys version",
        'bash -c "tmsh -q show sys version"',
    ]

    for command in commands:
        rc, out, err = ssh_exec(host, user, password, command)
        text = "\n".join(x for x in (out, err) if x)
        if rc == 0 and re.search(r"\bVersion\b", text, re.I):
            version = None
            build = None
            edition = None

            m = re.search(r"(?mi)^\s*Version\s+(\S+)", text)
            if m:
                version = m.group(1)

            m = re.search(r"(?mi)^\s*Build\s+(\S+)", text)
            if m:
                build = m.group(1)

            m = re.search(r"(?mi)^\s*Edition\s+(.+?)\s*$", text)
            if m:
                edition = m.group(1).strip()

            # "Hotfix List" is a heading followed by installed hotfix IDs;
            # it is not itself the hotfix name.
            hotfix_ids = sorted(set(re.findall(r"\bID\d+(?:-\d+)?\b", text)))

            parts = []
            if version:
                parts.append(f"version={version}")
            if build:
                parts.append(f"build={build}")
            if edition:
                parts.append(f"edition={edition}")
            if hotfix_ids:
                parts.append(f"hotfix_ids={len(hotfix_ids)}")

            return True, ", ".join(parts) if parts else first_line(text)

    return False, "unable to retrieve 'show sys version'"


def test_bash(host, user, password):
    marker = "__F5_ENV_PROBE_BASH_OK__"
    # Harmless: just start bash long enough to print a marker.
    command = f'bash -c "printf {marker}"'
    rc, out, err = ssh_exec(host, user, password, command)
    return rc == 0 and marker in out


def remote_probe(host):
    print(f"\n=== F5 probe: {host} ===")

    user = os.environ.get("USER", "")
    regular_pass = os.environ.get("SSHPASS", "")
    privileged_pass = os.environ.get("SSHPASSNET", "")

    if not user:
        add("FAIL", f"{host}: account probe", "USER is not set")
        return

    # Regular account (lands in tmsh)
    if regular_pass:
        ok, detail = retrieve_version(host, user, regular_pass, privileged=False)
        if ok:
            add("PASS", f"{host}: regular SSH / BIG-IP version", detail)
        else:
            add("FAIL", f"{host}: regular SSH / BIG-IP version", detail)

        if test_bash(host, user, regular_pass):
            add(
                "FAIL",
                f"{host}: regular user bash restriction",
                f"{user} CAN enter bash; check Cisco ISE policy",
            )
        else:
            add(
                "PASS",
                f"{host}: regular user bash restriction",
                f"{user} cannot enter bash",
            )
    else:
        add("SKIP", f"{host}: regular-account probe", "SSHPASS not set")

    # Privileged account (also lands in tmsh; use bash -c for bash commands)
    privileged_user = f"{user}_net"
    if privileged_pass:
        ok, detail = retrieve_version(host, privileged_user, privileged_pass, privileged=True)
        if ok:
            add("PASS", f"{host}: privileged SSH / BIG-IP version", detail)
        else:
            add("FAIL", f"{host}: privileged SSH / BIG-IP version", detail)

        if test_bash(host, privileged_user, privileged_pass):
            add(
                "PASS",
                f"{host}: privileged bash access",
                f"{privileged_user} can enter bash",
            )
        else:
            add(
                "WARN",
                f"{host}: privileged bash access",
                f"{privileged_user} could not enter bash",
            )
    else:
        add("SKIP", f"{host}: privileged-account probe", "SSHPASSNET not set")


def summary():
    counts = {}
    for r in RESULTS:
        counts[r.status] = counts.get(r.status, 0) + 1

    print("\n=== Summary ===")
    order = ["PASS", "FAIL", "WARN", "SKIP", "INFO"]
    print("  ".join(f"{k}={counts.get(k, 0)}" for k in order))

    if counts.get("FAIL", 0):
        return 1
    return 0


def parse_args():
    p = argparse.ArgumentParser(
        description="Probe the jump-host environment and optional F5 connectivity."
    )
    p.add_argument(
        "--host",
        action="append",
        default=[],
        metavar="F5",
        help="F5 hostname/IP to probe; may be specified multiple times",
    )
    return p.parse_args()


def main():
    args = parse_args()

    print("F5 Migration Validator - Environment Probe")
    print("Read-only probe; no configuration changes are made.")

    local_probe()

    for host in args.host:
        remote_probe(host)

    return summary()


if __name__ == "__main__":
    sys.exit(main())
