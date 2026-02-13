# SystemdTimer-LinuxPersistenceStash

A lightweight, LotL Linux persistence tool created for the purpose of periodically collecting valuable information regarding the target machine using systemd and python. Includes install.sh and uninstall.sh for easy deployment and clean-up. This tool prioritizes stealth and long-term persistence and is designed to work in conjunction with tools like a beacon or c2. After initial access and privilege escelation have been achieved, this tool uses root privileges in order to inconspicuously stash information that can be used to enhance knowledge regarding the attack surface.

## Overview

**SystemdTimer-LinuxPersistenceStash** runs as a systemd timer and service to regularly collect detailed system facts—hostname, OS info, network configuration, active services, user sessions, SSH indicators, and secret hints (and optionally secret values) and appends each run's output as a single-line JSON document to `/var/lib/timer-stash/stash.jsonl`.

### Key Features

- **Periodic collection**: Runs at 20 and 40 minutes past every hour, with a jitter of 8 minutes by default
- **Persistent storage**: Appends JSON records to a JSONL file for historical analysis
- **Minimal dependencies**: Python 3 standard library only; no third-party packages
- **Resilient**: Graceful fallbacks and error capture for missing tools or permissions

## Installation

### Prerequisites

- Targets a Linux system with Python 3.6+ installed
- Root level permissions required to install systemd files

### Quick Install

```bash
chmod + x ./install
sudo ./install.sh
```

This will:
1. Create a dedicated `timerstash` system user and group
2. Install the Python script to `/usr/libexec/timer-stash/`
3. Copy systemd unit files to `/etc/systemd/system/`
4. Create state directory `/var/lib/timer-stash/` (mode 0750)
5. Enable and start the timer

### Purge Source After Install

To remove the cloned repository after successful installation:

```bash
sudo ./install.sh --purge-source
```

This is a good way to clean up artifcats unnecessary for the service to run post-installation. The script will be accessed from usr/libexec/, not the cloned directory. It is a good idea to use the --purge-source option because you never know how quickly your initial access will be taken away. Additionally, this is the only way to delete the cloned git repo directory automatically, as uninstall.sh only cleans up files used by the service.


Clone the repo again to uninstall at any point.

### Example output following successful install
Created symlink '/etc/systemd/system/timers.target.wants/timer-stash.timer' → '/etc/systemd/system/timer-stash.timer'.
[✓] timer-stash installed.
● timer-stash.timer - Maintains System Inventory Backup
     Loaded: loaded (/etc/systemd/system/timer-stash.timer; enabled; preset: enabled)
     Active: active (waiting) since Fri 2026-02-13 16:23:17 EST; 9ms ago
 Invocation: 4d2d0f44745d460a80cd2d9fad8f39d6
    Trigger: Fri 2026-02-13 16:34:54 EST; 11min left
   Triggers: ● timer-stash.service

Feb 13 16:23:17 fedora-server.novalocal systemd[1]: Started timer-stash.timer - Maintains System Inventory Backup.
Fri 2026-02-13 16:34:54 EST  11min Fri 2026-02-13 16:17:50 EST            - timer-stash.timer            timer-stash.service
[cyberrange@fedora-server SystemdTimer-LinuxPersistenceStash]$ 

## Uninstallation

```bash
chmod +x uninstall.sh
sudo ./uninstall.sh
```

This will:
- Stop and disable the systemd timer
- Remove unit files, code, and state directory
- Delete the `timerstash` user

## Usage

### Operating on stash.jsonl (can be done from victim machine in /var/lib/timer-stash/ or on the attacker machine after exfiltrating)

```bash
# Tail the JSONL file (most recent runs) -- 
tail -f stash.jsonl

# Pretty-print most recent record
jq . < stash.jsonl | tail -1

# View timer status
systemctl status timer-stash.timer


### Run Manually (Standalone)

The underlying script can be run directly for one-time collection:

```bash
python3 /usr/libexec/timer-stash/stashinfo.py [options]
```

### OpSec Consideration (Logs and Evidence Created)
The tool is designed to blend-in rather than be invisible. Evidence of the tool exists within /var/lib/timer-stash and /usr/libexec.

Logs of the timer running can be found in journalctl. Limiting run frequency decreases noise. Changing names of timer-stash files and of the timerstash user will help those entries blend in when they are seen if the name *looks* like it belongs on the system.

#### Available Options

```
--output FILE               Write JSON to file instead of stdout
--compact                   Emit compact JSON (no pretty print)
--timeout-cmd SECONDS       Command timeout (default: 5)
--include-secret-values     Include secret values (sensitive)
--search-roots ROOT1,ROOT2  Comma-separated roots for secret scan (default: /etc,/opt)
--search-exclude DIR1,DIR2  Comma-separated dirs to exclude (default: /proc,/sys,/dev,/run)
--max-depth N               Max directory depth for secret scan (default: 3)
--no-network                Skip network collection
--no-services               Skip services collection
--no-logins                 Skip login sessions collection
--no-secrets                Skip secret hints scan
```

- Add desired flag to script execution within timer-stash.service

### Configure Collection Schedule

Edit `/etc/systemd/system/timer-stash.timer` to change the schedule:

```ini
[Timer]
OnCalendar=*-*-* *:05,20,40:00    # Runs at 05, 20, 40 minutes of every hour
Persistent=true                   # Run on boot if a run was missed from downtime
AccuracySec=1min                  # ±1 min accuracy
RandomizedDelaySec=15m            # Random delay up to 15 min (avoid thundering herd)
```


## Collected Data

Each JSON document contains:

```json
{
  "schema_version": "1.0",
  "run_id": "uuid-v4",
  "timestamp": "RFC3339",
  "identity": {
    "hostname": "...",
    "user": "...",
    "uid": 0,
    "gid": 0
  },
  "os": {
    "name": "ubuntu",
    "version_id": "20.04",
    "pretty_name": "Ubuntu 20.04.2 LTS"
  },
  "uptime_seconds": 123456,
  "network": {
    "addresses": ["192.168.1.10/24", "fe80::1/64"],
    "routes_summary": ["default via 192.168.1.1 dev eth0"],
    "listening_ports_summary": ["tcp:22", "tcp:80"],
    "dns_resolvers": ["8.8.8.8", "8.8.4.4"]
  },
  "users": {
    "local_usernames": ["root", "alice"],
    "current_user_groups": ["timerstash"]
  },
  "ssh_indicators": {
    "home_ssh_dir_exists": true,
    "home_ssh_perms_ok": "rwx------",
    "system_sshd_config_present": true
  },
  "services": {
    "active_service_names": ["ssh", "cron", "nginx"]
  },
  "logins": {
    "sessions_summary": ["user:alice tty:pts/0 state:online"]
  },
  "secret_hints": [
    {"path": "/etc/app/.env", "key": "API_KEY", "value": "examplekeyvalue(if --include-sercret-values is specified for stashinfo.py)"}
  ],
  "errors": []
}
```

## Configuration

### Persistent File Location

Data is appended to `/var/lib/timer-stash/stash.jsonl` (one JSON record per line).

### Service User & Permissions

- Service runs as unprivileged `timerstash` user (UID ~100+)
- State directory is mode `0750` (readable/writable by `timerstash` only)

## Security Considerations

- **Sandboxing**: Service uses strict `ProtectSystem`, `NoNewPrivileges`, `PrivateTmp`
- **Limited Privileges**: Runs as unprivileged `timerstash` user, no capabilities
- **Secret Redaction**: By default, detected API keys/tokens are not included; use `--include-secret-values` only in authorized/competition/lab settings
- **File Permissions**: State directory is mode 0750; only `timerstash` user can read the stash

## Troubleshooting

### Timer not running

```bash
# Check if timer is enabled and active
systemctl is-enabled timer-stash.timer
systemctl is-active timer-stash.timer

# View last run output
journalctl -u timer-stash.service -n 50

# Manually trigger a run (for testing)
sudo systemctl start timer-stash.service
```

### Stash file not being written

```bash
# Check directory permissions
ls -ld /var/lib/timer-stash/

# Verify service user exists
id timerstash

# Check service status
systemctl status timer-stash.service
```


## Performance & Storage

- **Typical run time**: 1–5 seconds (depending on system load and installed tools)
- **Typical JSON size**: 2–10 KB per run
- **Disk usage**: ~2–10 MB per day at 15-minute intervals (depends on collected data)
- **Retention**: Append-only; manually archive or rotate `/var/lib/timer-stash/stash.jsonl` as needed
- **Uninstallation** The tool is designed to clean up after itself using the uninstall.sh script. This will reset the local stash on the victim machine. *IF YOU DID NOT USE --purge-source AT INSTALL, YOU WILL STILL NEED TO MANUALLY REMOVE THE DIRECTORY THE TOOL WAS DOWNLOADED TO. UNINSTALL SCRIPT ONLY CLEANS UP FILES USED BY THE SERVICE, NOT THE CLONED DIRECTORY*

## Opportunity for Improvement
- While it is certainly possible via the script arguments to change placement of service/script files, I think it could be made easier by incorporating user-input at install
- Another addition involving user-input at install would be the ability to quickly change the name of the service and other recognizable patterns like the systemd descriptions. This would allow for easier and stealthier redeployment after blue-team discovers the first deployment
- The tool could be adapted to deliver consequential payloads on timer runs in addition to stashing information

## Resources
- https://dev.to/nithinbharathwaj/master-python-system-programming-from-subprocess-commands-to-advanced-process-control-techniques-31l7
- https://www.man7.org/linux/man-pages/man1/systemd.1.html
- https://www.man7.org/linux/man-pages/man5/systemd.timer.5.html
- https://github.com/camperboy1000/explosive-timers/blob/main/bootstrap.sh


The above resources served as helpful references regarding system programming in python, systemd, timers, and malicious applications and obfuscation for systemdtimers
