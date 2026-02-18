#!/usr/bin/env python3
#Jack O'Donnell, jro9456@rit.edu
"""
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
- Resilient with fallbacks and error capture.
- Secret values are redacted by default; use --include-secret-values to include them.
- Tested on systemd-based distros; handles missing tools gracefully.
"""

import argparse
import getpass
import grp
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set

# ============================================
# Defaults / Tunables
# ============================================
DEFAULT_CMD_TIMEOUT = 5  # [improvement] configurable timeout
DEFAULT_SECRET_MAX_FILE_BYTES = 512 * 1024  # 512 KiB cap per env-like file
DEFAULT_SEARCH_ROOTS = "/etc,/opt"
DEFAULT_SEARCH_EXCLUDE = "/proc,/sys,/dev,/run"  # [improvement] safe defaults


# ============================================
# Utility: time & commands
# ============================================
def rfc3339_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_cmd(cmd: List[str], timeout: int = DEFAULT_CMD_TIMEOUT) -> Tuple[int, str, str]:
    """Run a command safely, returning (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            check=False,
            env=dict(os.environ, LC_ALL="C"),  # [improvement] stable locale
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as e:
        return 127, "", f"not found: {e}"
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or ""), f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", f"exception: {e!r}"


# ============================================
# OS information
# ============================================
def parse_os_release(errors: List[str]) -> Dict[str, str]:
    result = {"name": "", "version_id": "", "pretty_name": ""}
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
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
        errors.append(f"os-release: failed to parse /etc/os-release: {e!r}")
    return result


def read_uptime_seconds(errors: List[str]) -> int:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            first = f.read().strip().split()[0]
            return int(float(first))
    except Exception as e:
        errors.append(f"uptime: failed to read /proc/uptime: {e!r}")
        return 0


# ============================================
# Network
# ============================================
def collect_network_addresses(errors: List[str]) -> List[str]:
    """Return addresses in CIDR, both IPv4/IPv6, using `ip` if available."""
    addrs: Set[str] = set()
    ip_bin = shutil.which("ip")
    if ip_bin:
        for fam in (("inet",), ("inet6",)):
            rc, out, err = run_cmd([ip_bin, "-o", "-f", fam[0], "addr", "show"])
            if rc == 0:
                for line in out.splitlines():
                    # "... inet 192.168.1.10/24 ..." or "... inet6 fe80::1/64 ..."
                    m = re.search(r"\sinet6?\s+([0-9a-fA-F\.:]+/\d+)", line)
                    if m:
                        addrs.add(m.group(1))
            else:
                errors.append(f"network: `ip -o -f {fam[0]} addr show` failed: {err.strip()}")
    else:
        errors.append("network: `ip` command not found; addresses unavailable")

    return sorted(addrs)


def collect_routes_summary(errors: List[str]) -> List[str]:
    routes: List[str] = []
    ip_bin = shutil.which("ip")
    if ip_bin:
        for args in (["route", "show"], ["-6", "route", "show"]):
            rc, out, err = run_cmd([ip_bin, *args])
            if rc == 0 and out.strip():
                routes.extend([ln.strip() for ln in out.strip().splitlines()])
            elif rc != 0 and err.strip():
                args_str = " ".join(args)
                errors.append(f"routes: `ip {args_str}` failed: {err.strip()}")
    else:
        errors.append("routes: `ip` command not found; routes unavailable")
    return routes


def collect_listening_ports_summary(errors: List[str]) -> List[str]:
    """
    Returns entries like ["tcp:22", "udp:68"] from ss/netstat (listening, numeric).
    """
    ports: Set[str] = set()

    def record(proto: str, local: str):
        # Normalize proto (tcp6->tcp, udp6->udp)
        proto_norm = "tcp" if proto.startswith("tcp") else "udp"
        port = None
        if local.startswith("["):
            m = re.match(r"\[.*\]:(\d+)$", local)  # [::]:80
            if m:
                port = m.group(1)
        else:
            if ":" in local:
                port = local.rsplit(":", 1)[-1]
        if port and port.isdigit():
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
            errors.append(f"ports: `ss -lntuH` failed: {err.strip()}")
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
                errors.append(f"ports: `netstat -lntu` failed: {err.strip()}")
        else:
            errors.append("ports: Neither `ss` nor `netstat` found; ports unavailable")

    def sort_key(x: str) -> Tuple[str, int]:
        proto, port = x.split(":")
        try:
            return (proto, int(port))
        except ValueError:
            return (proto, 0)

    return sorted(ports, key=sort_key)


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
        errors.append(f"dns: failed to parse /etc/resolv.conf: {e!r}")
    return resolvers


# ============================================
# Users / Groups
# ============================================
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
        errors.append(f"users: failed to enumerate users: {e!r}")

    group_names: List[str] = []
    try:
        seen = set()
        for gid in os.getgroups():
            try:
                name = grp.getgrgid(gid).gr_name
                if name not in seen:
                    group_names.append(name)
                    seen.add(name)
            except KeyError:
                continue
    except Exception as e:
        errors.append(f"users: failed to get current user groups: {e!r}")

    return {
        "local_usernames": sorted(set(usernames)),
        "current_user_groups": sorted(group_names),  # [improvement] stable order
    }


# ============================================
# SSH indicators
# ============================================
def stat_mode_to_rwx(mode: int) -> str:
    mapping = (
        (stat.S_IRUSR, "r"), (stat.S_IWUSR, "w"), (stat.S_IXUSR, "x"),
        (stat.S_IRGRP, "r"), (stat.S_IWGRP, "w"), (stat.S_IXGRP, "x"),
        (stat.S_IROTH, "r"), (stat.S_IWOTH, "w"), (stat.S_IXOTH, "x"),
    )
    return "".join(ch if (mode & bit) else "-" for bit, ch in mapping)


def collect_ssh_indicators(errors: List[str]) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "home_ssh_dir_exists": False,
        "home_ssh_perms_ok": "",
        "system_sshd_config_present": False,
    }
    try:
        ssh_dir = Path.home() / ".ssh"
        if ssh_dir.is_dir():
            info["home_ssh_dir_exists"] = True
            try:
                mode = stat.S_IMODE(ssh_dir.stat().st_mode)
                info["home_ssh_perms_ok"] = stat_mode_to_rwx(mode)
            except Exception as e:
                errors.append(f"ssh: failed to stat ~/.ssh: {e!r}")
        info["system_sshd_config_present"] = Path("/etc/ssh/sshd_config").is_file()
    except Exception as e:
        errors.append(f"ssh: failed to collect SSH indicators: {e!r}")
    return info


# ============================================
# Services
# ============================================
def collect_services(errors: List[str]) -> Dict[str, List[str]]:
    services: List[str] = []
    systemctl = shutil.which("systemctl")
    if systemctl:
        rc, out, err = run_cmd([systemctl, "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if parts:
                    unit = parts[0]
                    services.append(unit[:-8] if unit.endswith(".service") else unit)
        else:
            errors.append(f"services: `systemctl list-units` failed: {err.strip()}")
    else:
        service_bin = shutil.which("service")
        if service_bin:
            rc, out, err = run_cmd([service_bin, "--status-all"])
            if rc == 0:
                for line in out.splitlines():
                    m = re.search(r"\[\s*\+\s*\]\s+(\S+)", line)
                    if m:
                        services.append(m.group(1))
            else:
                errors.append(f"services: `service --status-all` failed: {err.strip()}")
        else:
            errors.append("services: Neither `systemctl` nor `service` found; services unavailable")
    return {"active_service_names": sorted(set(services))}


# ============================================
# Logins
# ============================================
def collect_logins(errors: List[str]) -> Dict[str, List[str]]:
    sessions: List[str] = []
    who_bin = shutil.which("who")
    if who_bin:
        rc, out, err = run_cmd([who_bin])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    user, tty = parts[0], parts[1]
                    sessions.append(f"user:{user} tty:{tty} state:online")
        else:
            errors.append(f"logins: `who` failed: {err.strip()}")
    else:
        errors.append("logins: `who` not found; sessions unavailable")
    return {"sessions_summary": sessions}


# ============================================
# Identity
# ============================================
def collect_identity(errors: List[str]) -> Dict[str, Any]:
    try:
        hostname = socket.gethostname()
    except Exception as e:
        errors.append(f"identity: failed to get hostname: {e!r}")
        hostname = ""

    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""

    try:
        uid, gid = os.getuid(), os.getgid()
    except Exception as e:
        errors.append(f"identity: failed to get uid/gid: {e!r}")
        uid, gid = -1, -1

    return {"hostname": hostname, "user": user, "uid": uid, "gid": gid}


# ============================================
# Network aggregator
# ============================================
def collect_network(errors: List[str]) -> Dict[str, Any]:
    return {
        "addresses": collect_network_addresses(errors),
        "routes_summary": collect_routes_summary(errors),
        "listening_ports_summary": collect_listening_ports_summary(errors),
        "dns_resolvers": collect_dns_resolvers(errors),
    }


# ============================================
# Secret scanning
# ============================================
_SECRET_KEY_PATTERN = re.compile(
    r"(API[_-]?KEY|ACCESS[_-]?KEY|SECRET(?:[_-]?KEY)?|TOKEN|PASSWORD|PRIVATE[_-]?KEY|flag\{[^}\n]{1,200}\)",
    re.IGNORECASE,
)

def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample  # [improvement] quick heuristic


def parse_env_file(path: Path, include_values: bool, errors: List[str]) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    try:
        # [improvement] size cap & symlink skip
        if path.is_symlink():
            return items
        st = path.stat()
        if st.st_size > DEFAULT_SECRET_MAX_FILE_BYTES:
            return items

        with path.open("rb") as fb:
            head = fb.read(4096)
            if _looks_binary(head):
                return items
            fb.seek(0)

            # Decode as text
            data = fb.read().decode("utf-8", errors="ignore")

        for raw in data.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Support "export KEY=value" as well
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if _SECRET_KEY_PATTERN.search(key):
                item = {"path": str(path), "key": key}
                if include_values:
                    item["value"] = val
                items.append(item)
    except PermissionError:
        # Expected on some files; silent skip
        pass
    except Exception as e:
        errors.append(f"secrets: failed to parse {path}: {e!r}")
    return items


def limited_walk(root: Path, max_depth: int, exclude_dirs: Set[Path]):
    """
    Walks up to max_depth levels below root (0 means only root) and skips excluded dirs.
    """
    try:
        root = root.resolve()
    except Exception:
        # If we can't resolve, fall back to given
        root = Path(root)

    base_parts = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        cur_dir = Path(dirpath)
        # [improvement] prune excluded prefixes
        pruned = []
        for i in range(len(dirnames) - 1, -1, -1):
            child = cur_dir / dirnames[i]
            try:
                child_resolved = child.resolve()
            except Exception:
                child_resolved = child
            if any(str(child_resolved).startswith(str(ex)) for ex in exclude_dirs):
                pruned.append(dirnames[i])
                del dirnames[i]
        # depth control
        try:
            current_depth = len(cur_dir.resolve().parts) - base_parts
        except Exception:
            current_depth = len(cur_dir.parts) - base_parts
        if current_depth > max_depth:
            dirnames[:] = []
            continue
        yield dirpath, dirnames, filenames


def collect_secret_hints(
    errors: List[str],
    include_values: bool,
    search_roots: List[str],
    max_depth: int,
    exclude_dirs: List[str],
) -> List[Dict[str, str]]:
    hints: List[Dict[str, str]] = []

    # [improvement] sanitize & prepare targets
    targets = []
    for root in search_roots:
        p = Path(root).resolve()
        if p.exists() and p.is_dir():
            targets.append(p)

    exclude_set = set(Path(e).resolve() for e in exclude_dirs if e)

    for root in targets:
        try:
            for dirpath, _, filenames in limited_walk(root, max_depth=max(0, max_depth), exclude_dirs=exclude_set):
                for fn in filenames:
                    fl = fn.lower()
                    if fl == ".env" or fl == "config.env" or fl.endswith(".env"):
                        path = Path(dirpath) / fn
                        hints.extend(parse_env_file(path, include_values, errors))
        except PermissionError:
            continue
        except Exception as e:
            errors.append(f"secrets: error scanning {root}: {e!r}")

    # dedupe
    seen = set()
    uniq: List[Dict[str, str]] = []
    for item in hints:
        sig = (item["path"], item["key"], item.get("value", "__NO_VAL__"))
        if sig not in seen:
            uniq.append(item)
            seen.add(sig)
    return uniq


# ============================================
# Main
# ============================================
def main():
    global DEFAULT_CMD_TIMEOUT
    
    parser = argparse.ArgumentParser(description="Generate Linux system JSON facts.")
    parser.add_argument("-o", "--output", help="write JSON to file instead of stdout")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON (no pretty print)")

    # knobs
    parser.add_argument("--timeout-cmd", type=int, default=DEFAULT_CMD_TIMEOUT, help=f"command timeout seconds (default: {DEFAULT_CMD_TIMEOUT})")
    parser.add_argument("--include-secret-values", action="store_true", help="include secret values in output (⚠️ sensitive)")
    parser.add_argument("--search-roots", default=DEFAULT_SEARCH_ROOTS, help=f"comma-separated roots for secret scan (default: {DEFAULT_SEARCH_ROOTS})")
    parser.add_argument("--search-exclude", default=DEFAULT_SEARCH_EXCLUDE, help=f"comma-separated dirs to exclude from scanning (default: {DEFAULT_SEARCH_EXCLUDE})")
    parser.add_argument("--max-depth", type=int, default=3, help="maximum directory depth for secret scan (default: 3)")

    # allow disabling collectors
    parser.add_argument("--no-network", action="store_true", help="skip network collection")
    parser.add_argument("--no-services", action="store_true", help="skip services collection")
    parser.add_argument("--no-logins", action="store_true", help="skip login sessions collection")
    parser.add_argument("--no-secrets", action="store_true", help="skip secret hints scan")

    args = parser.parse_args()

    # apply timeout globally
    DEFAULT_CMD_TIMEOUT = max(1, int(args.timeout_cmd))

    errors: List[str] = []

    doc: Dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": str(uuid.uuid4()),
        "timestamp": rfc3339_now(),
        "identity": collect_identity(errors),
        "os": parse_os_release(errors),
        "uptime_seconds": read_uptime_seconds(errors),
        "network": {} if args.no_network else collect_network(errors),
        "users": collect_users(errors),
        "ssh_indicators": collect_ssh_indicators(errors),
        "services": {} if args.no_services else collect_services(errors),
        "logins": {} if args.no_logins else collect_logins(errors),
        "secret_hints": [] if args.no_secrets else collect_secret_hints(
            errors=errors,
            include_values=args.include_secret_values,
            search_roots=[s for s in args.search_roots.split(",") if s],
            max_depth=args.max_depth,
            exclude_dirs=[e for e in args.search_exclude.split(",") if e],
        ),
        "errors": errors,
    }

    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False, indent=None if args.compact else 2)
            print(f"Wrote: {args.output}")
        else:
            json.dump(doc, sys.stdout, ensure_ascii=False, indent=None if args.compact else 2)
            if not args.compact:
                sys.stdout.write("\n")
    except Exception as e:
        print(f"output: failed to write JSON: {e!r}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
