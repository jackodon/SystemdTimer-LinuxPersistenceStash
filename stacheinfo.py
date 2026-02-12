#!/usr/bin/env python3
"""
linux_inventory.py

Collects system facts from a Linux OS and emits a JSON document matching this structure:

{
  "schema_version": "1.0",
  "run_id": "uuid-v4",
  "timestamp": "RFC3339",
  "identity": {...},
  "os": {...},
  "uptime_seconds": 12345,
  "network": {...},
  "users": {...},
  "ssh_indicators": {...},
  "services": {...},
  "logins": {...},
  "secret_hints": [...],
  "errors": [...]
}

- Standard library only; no third-party dependencies.
- Designed to be resilient with fallbacks and error capture.
- Secret values are redacted by default; use --include-secret-values to show them.

Tested on systemd-based distros. Works best when `ip`, `ss`, and `systemctl` are present. Does include error handling for missing dependencies
"""

import argparse
import getpass
import grp
import json
import os
import pwd
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set


def rfc3339_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_cmd(cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
    """Run a command safely, returning (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", f"timeout: {e}"
    except Exception as e:
        return 1, "", str(e)


def parse_os_release(errors: List[str]) -> Dict[str, str]:
    result = {"name": "", "version_id": "", "pretty_name": ""}
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            data = f.read()
        for line in data.splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip().strip('"')
            if k == "ID":
                result["name"] = v
            elif k == "VERSION_ID":
                result["version_id"] = v
            elif k == "PRETTY_NAME":
                result["pretty_name"] = v
    except Exception as e:
        errors.append(f"failed to parse /etc/os-release: {e!r}")
    return result


def read_uptime_seconds(errors: List[str]) -> int:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            first = f.read().strip().split()[0]
            return int(float(first))
    except Exception as e:
        errors.append(f"failed to read /proc/uptime: {e!r}")
        return 0


def collect_network_addresses(errors: List[str]) -> List[str]:
    """Return addresses in CIDR, both IPv4/IPv6, using `ip` if available."""
    addrs: Set[str] = set()
    ip_bin = shutil.which("ip")
    if ip_bin:
        for fam_flag in (("-f", "inet"), ("-f", "inet6")):
            rc, out, err = run_cmd([ip_bin, "-o", fam_flag[0], fam_flag[1], "addr", "show"])
            if rc == 0:
                for line in out.splitlines():
                    # Format: <idx>: <iface> <fam> <addr>/<prefix> ...
                    m = re.search(r"\sinet6?\s+([0-9a-fA-F\.:]+/\d+)", line)
                    if m:
                        addrs.add(m.group(1))
            else:
                errors.append(f"`ip addr show` failed for {fam_flag[1]}: {err.strip()}")
    else:
        errors.append("`ip` command not found; network addresses unavailable")

    return sorted(addrs)


def collect_routes_summary(errors: List[str]) -> List[str]:
    routes: List[str] = []
    ip_bin = shutil.which("ip")
    if ip_bin:
        for fam_flag, label in ((("route", "show"), "ipv4"), (("-6", "route", "show"), "ipv6")):
            cmd = [ip_bin, *fam_flag]
            rc, out, err = run_cmd(cmd)
            if rc == 0 and out.strip():
                for line in out.strip().splitlines():
                    # Keep raw line to preserve detail; optionally prefix with family if desired
                    routes.append(line.strip())
            elif rc != 0 and err.strip():
                errors.append(f"`{' '.join(cmd)}` failed: {err.strip()}")
    else:
        errors.append("`ip` command not found; routes unavailable")
    return routes


def collect_listening_ports_summary(errors: List[str]) -> List[str]:
    """
    Returns entries like ["tcp:22", "udp:68"] from ss/netstat (listening, numeric).
    De-duplicates and sorts.
    """
    ports: Set[str] = set()

    def record(proto: str, local: str):
        port = None
        if local.startswith("["):
            # [::]:80
            m = re.match(r"\[.*\]:(\d+)$", local)
            if m:
                port = m.group(1)
        else:
            # Split by last colon
            if ":" in local:
                port = local.rsplit(":", 1)[-1]
        if port and port.isdigit():
            proto_norm = "tcp" if proto.startswith("tcp") else "udp"
            ports.add(f"{proto_norm}:{port}")

    ss_bin = shutil.which("ss")
    if ss_bin:
        rc, out, err = run_cmd([ss_bin, "-lntuH"])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    proto = parts[0]
                    local = parts[4]
                    record(proto, local)
        else:
            errors.append(f"`ss -lntu` failed: {err.strip()}")
    else:
        netstat_bin = shutil.which("netstat")
        if netstat_bin:
            rc, out, err = run_cmd([netstat_bin, "-lntu"])
            if rc == 0:
                for line in out.splitlines():
                    if line.startswith("Proto") or not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 4:
                        proto = parts[0]
                        local = parts[3]
                        record(proto, local)
            else:
                errors.append(f"`netstat -lntu` failed: {err.strip()}")
        else:
            errors.append("Neither `ss` nor `netstat` found; listening ports unavailable")

    return sorted(ports, key=lambda x: (x.split(":")[0], int(x.split(":")[1])))


def collect_dns_resolvers(errors: List[str]) -> List[str]:
    resolvers: List[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        resolvers.append(parts[1])
    except Exception as e:
        errors.append(f"failed to parse /etc/resolv.conf: {e!r}")
    return resolvers


def collect_users(errors: List[str]) -> Dict[str, List[str]]:
    usernames: List[str] = []
    try:
        # Include root and users with UID >= 1000 (typical non-system accounts)
        for p in pwd.getpwall():
            try:
                if p.pw_uid == 0 or p.pw_uid >= 1000:
                    usernames.append(p.pw_name)
            except Exception:
                continue
    except Exception as e:
        errors.append(f"failed to enumerate users: {e!r}")

    group_names: List[str] = []
    try:
        gids = os.getgroups()
        seen = set()
        for gid in gids:
            try:
                name = grp.getgrgid(gid).gr_name
                if name not in seen:
                    group_names.append(name)
                    seen.add(name)
            except KeyError:
                # Unknown group
                continue
    except Exception as e:
        errors.append(f"failed to get current user groups: {e!r}")

    return {
        "local_usernames": sorted(set(usernames)),
        "current_user_groups": group_names,
    }


def stat_mode_to_rwx(mode: int) -> str:
    # Only owner/group/other rwx bits
    perms = ""
    mapping = (
        (stat.S_IRUSR, "r"), (stat.S_IWUSR, "w"), (stat.S_IXUSR, "x"),
        (stat.S_IRGRP, "r"), (stat.S_IWGRP, "w"), (stat.S_IXGRP, "x"),
        (stat.S_IROTH, "r"), (stat.S_IWOTH, "w"), (stat.S_IXOTH, "x"),
    )
    for bit, ch in mapping:
        perms += ch if (mode & bit) else "-"
    return perms


def collect_ssh_indicators(errors: List[str]) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "home_ssh_dir_exists": False,
        "home_ssh_perms_ok": "",
        "system_sshd_config_present": False,
    }
    try:
        home = Path.home()
        ssh_dir = home / ".ssh"
        if ssh_dir.exists() and ssh_dir.is_dir():
            info["home_ssh_dir_exists"] = True
            try:
                st = ssh_dir.stat()
                mode = stat.S_IMODE(st.st_mode)
                info["home_ssh_perms_ok"] = stat_mode_to_rwx(mode)
            except Exception as e:
                errors.append(f"failed to stat ~/.ssh: {e!r}")
        else:
            info["home_ssh_dir_exists"] = False
            info["home_ssh_perms_ok"] = ""

        info["system_sshd_config_present"] = Path("/etc/ssh/sshd_config").is_file()
    except Exception as e:
        errors.append(f"failed to collect SSH indicators: {e!r}")

    return info


def collect_services(errors: List[str]) -> Dict[str, List[str]]:
    services: List[str] = []
    systemctl = shutil.which("systemctl")
    if systemctl:
        rc, out, err = run_cmd([systemctl, "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"])
        if rc == 0:
            for line in out.splitlines():
                # Example line: "sshd.service loaded active running OpenSSH Daemon"
                parts = line.split()
                if parts:
                    unit = parts[0]
                    if unit.endswith(".service"):
                        name = unit[:-8]
                    else:
                        name = unit
                    services.append(name)
        else:
            errors.append(f"`systemctl list-units` failed: {err.strip()}")
    else:
        # Fallback: parse `service --status-all` (less reliable)
        service_bin = shutil.which("service")
        if service_bin:
            rc, out, err = run_cmd([service_bin, "--status-all"])
            if rc == 0:
                for line in out.splitlines():
                    # Lines look like: " [ + ]  cron"
                    m = re.search(r"\[\s*\+\s*\]\s+(\S+)", line)
                    if m:
                        services.append(m.group(1))
            else:
                errors.append(f"`service --status-all` failed: {err.strip()}")
        else:
            errors.append("Neither `systemctl` nor `service` found; services unavailable")
    return {"active_service_names": sorted(set(services))}


def collect_logins(errors: List[str]) -> Dict[str, List[str]]:
    sessions: List[str] = []
    who_bin = shutil.which("who")
    if who_bin:
        rc, out, err = run_cmd([who_bin])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    user = parts[0]
                    tty = parts[1]
                    sessions.append(f"user:{user} tty:{tty} state:online")
        else:
            errors.append(f"`who` failed: {err.strip()}")
    else:
        errors.append("`who` not found; sessions unavailable")
    return {"sessions_summary": sessions}


def collect_identity(errors: List[str]) -> Dict[str, Any]:
    try:
        hostname = socket.gethostname()
    except Exception as e:
        errors.append(f"failed to get hostname: {e!r}")
        hostname = ""

    try:
        user = getpass.getuser()
    except Exception:
        # Fallback
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""

    try:
        uid = os.getuid()
        gid = os.getgid()
    except Exception as e:
        errors.append(f"failed to get uid/gid: {e!r}")
        uid, gid = -1, -1

    return {
        "hostname": hostname,
        "user": user,
        "uid": uid,
        "gid": gid,
    }


def collect_network(errors: List[str]) -> Dict[str, Any]:
    return {
        "addresses": collect_network_addresses(errors),
        "routes_summary": collect_routes_summary(errors),
        "listening_ports_summary": collect_listening_ports_summary(errors),
        "dns_resolvers": collect_dns_resolvers(errors),
    }


def parse_env_file(path: Path, include_values: bool) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # basic KEY=VALUE
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    # keys of interest
                    interesting = re.search(r"(API[_-]?KEY|ACCESS[_-]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY)", key, re.IGNORECASE)
                    if interesting:
                        item = {"path": str(path), "key": key}
                        if include_values:
                            item["value"] = val
                        items.append(item)
    except Exception:
        # Ignore per-file errors silently; not critical
        pass
    return items


def limited_walk(root: Path, max_depth: int):
    """
    Walks up to max_depth levels below root (0 means only root).
    """
    root = root.resolve()
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_depth = len(Path(dirpath).resolve().parts) - base_depth
        if current_depth > max_depth:
            # Prune
            dirnames[:] = []
            continue
        yield dirpath, dirnames, filenames


def collect_secret_hints(errors: List[str], include_values: bool, search_roots: List[str], max_depth: int) -> List[Dict[str, str]]:
    hints: List[Dict[str, str]] = []

    # Always check a couple of common example paths quickly
    common_paths = [Path("/etc/app/config.env"), Path("/opt/app/.env")]
    for p in common_paths:
        if p.is_file():
            hints.extend(parse_env_file(p, include_values))

    targets = []
    for root in search_roots:
        p = Path(root)
        if p.exists() and p.is_dir():
            targets.append(p)

    for root in targets:
        try:
            for dirpath, _, filenames in limited_walk(root, max_depth=max_depth):
                for fn in filenames:
                    # Consider common env patterns; keep narrow to avoid scanning huge trees
                    if fn.lower() in (".env", "config.env") or fn.lower().endswith(".env"):
                        path = Path(dirpath) / fn
                        hints.extend(parse_env_file(path, include_values))
        except PermissionError:
            # Skip silently; expected on system dirs
            continue
        except Exception as e:
            errors.append(f"error scanning {root}: {e!r}")

    # Deduplicate
    seen = set()
    uniq: List[Dict[str, str]] = []
    for item in hints:
        sig = (item["path"], item["key"], item.get("value", "__NO_VAL__"))
        if sig not in seen:
            uniq.append(item)
            seen.add(sig)
    return uniq


def main():
    parser = argparse.ArgumentParser(description="Generate Linux system JSON facts.")
    parser.add_argument("-o", "--output", help="write JSON to file instead of stdout")
    parser.add_argument("--include-secret-values", action="store_true", help="include secret values in output (⚠️ sensitive)")
    parser.add_argument("--search-roots", default="/etc,/opt", help="comma-separated roots for secret scan (default: /etc,/opt)")
    parser.add_argument("--max-depth", type=int, default=3, help="maximum directory depth for secret scan (default: 3)")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON (no pretty print)")
    args = parser.parse_args()

    errors: List[str] = []

    doc: Dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": str(uuid.uuid4()),
        "timestamp": rfc3339_now(),
        "identity": collect_identity(errors),
        "os": parse_os_release(errors),
        "uptime_seconds": read_uptime_seconds(errors),
        "network": collect_network(errors),
        "users": collect_users(errors),
        "ssh_indicators": collect_ssh_indicators(errors),
        "services": collect_services(errors),
        "logins": collect_logins(errors),
        "secret_hints": collect_secret_hints(
            errors=errors,
            include_values=args.include_secret_values,
            search_roots=[s for s in args.search_roots.split(",") if s],
            max_depth=max(0, args.max_depth),
        ),
        "errors": errors,
    }

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False, indent=None if args.compact else 2)
            print(f"Wrote: {args.output}")
        except Exception as e:
            print(f"Failed to write output file: {e!r}", file=sys.stderr)
            sys.exit(1)
    else:
        json.dump(doc, sys.stdout, ensure_ascii=False, indent=None if args.compact else 2)
        if not args.compact:
            sys.stdout.write("\n")


if __name__ == "__main__":
    main()