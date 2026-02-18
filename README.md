# firewalld-manager

An interactive TUI and CLI for managing [firewalld](https://firewalld.org/) — with built-in port risk assessment.

Browse all 263 known firewalld services, open/close ports with a confirmation dialog, run a one-command lockdown, and get detailed security explanations for any port you're about to expose.

---

## Features

- **Full-screen TUI** — arrow-key navigation, live search, colour-coded status
- **Risk assessment** — every port gets a score (0–100) with a human-readable explanation and notable CVEs
- **Lockdown** — close everything except SSH and HTTPS in one keystroke
- **Rich rules** — restrict a port to a specific source IP/CIDR from the action menu
- **CLI mode** — all operations available as direct shell commands for scripting
- **Safe by default** — SSH and HTTPS are flagged as protected; closing them requires extra confirmation
- **Permanent + runtime** — changes apply immediately and survive reboot (runtime-only is also available)

---

## Requirements

- Linux with [firewalld](https://firewalld.org/) installed and running
- `python-firewall` (the D-Bus client library that ships with firewalld)
- Python 3.10+
- `click`, `rich`, `prompt_toolkit` (installed automatically by pip)

---

## Installation

### Arch / Manjaro

```bash
sudo pacman -S firewalld python-firewall python-pip
sudo systemctl enable --now firewalld
pip install -e . --break-system-packages
```

### Ubuntu / Debian

```bash
sudo apt install firewalld python3-firewall python3-pip
sudo systemctl enable --now firewalld
pip install -e . --break-system-packages
```

### Fedora / RHEL / CentOS

```bash
sudo dnf install firewalld python3-firewall python3-pip
sudo systemctl enable --now firewalld
pip install -e .
```

### openSUSE

```bash
sudo zypper install firewalld python3-firewall python3-pip
sudo systemctl enable --now firewalld
pip install -e .
```

After installation the `firewall-manager` command is available system-wide.

### Permissions (polkit)

firewalld-manager communicates with firewalld over D-Bus. On some systems (Ubuntu in particular) the default polkit policy denies non-root users access to firewalld's config API.

**Quick fix** — just run with sudo:
```bash
sudo firewall-manager
```

**Permanent fix** — grant your user permission without sudo:
```bash
sudo tee /etc/polkit-1/rules.d/49-firewalld-manager.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.fedoraproject.FirewallD1") === 0 &&
        subject.isInGroup("sudo")) {
        return polkit.Result.YES;
    }
});
EOF
sudo systemctl restart polkit
```

After that, `firewall-manager` works without sudo. The rule grants any user in the `sudo` group full firewalld access — adjust the group name if needed.

If you hit the polkit error, the tool will print these instructions automatically.

---

## TUI — Interactive Mode

Start with no arguments:

```
firewall-manager
```

```
  firewalld-manager  │  Zone: public  │  ACTIVE  │  Target: default  │  Interface: wlp58s0
──────────────────────────────────────────────────────────────────────────────────────────
  Type to search  │  /: activate search  │  Esc: clear
──────────────────────────────────────────────────────────────────────────────────────────
Port     Proto   Service              Description            Status    Risk
────────────────────────────────────────────────────────────────────────────────────────
22       tcp     ssh                  Secure Shell Server    ● OPEN*   ███░░░░░ 35
5353     udp     mdns                 Multicast DNS          ● OPEN    ██░░░░░░ 30
546      udp     dhcpv6-client        DHCPv6 Client          ● OPEN    █░░░░░░░ 18
23       tcp     telnet               Telnet                 ○ closed  ████████ 98
3389     tcp     ms-wbt-server        RDP                    ○ closed  ████████ 93
445      tcp     samba                Windows File Sharing   ○ closed  ████████ 92
...

  [↑↓] Navigate  [Enter] Action  [O] Open  [C] Close  [L] Lockdown  [Z] Zone  [R] Refresh  [Q] Quit
```

### Keybindings

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate the service list |
| `Enter` | Open the action menu for the selected service |
| `O` | Open the selected service (permanent + runtime) |
| `C` | Close the selected service |
| `L` | Lockdown dialog (close everything except SSH + HTTPS) |
| `Z` | Switch firewall zone |
| `R` | Refresh / reload from firewalld |
| `/` | Activate search field |
| Type anything | Filter the list live (by service name, port number, or description) |
| `Esc` | Clear search |
| `Q` / `Ctrl-C` | Quit |

### Action Menu (Enter)

Pressing `Enter` on any service opens a context menu:

```
 ssh
  Secure Shell Server  [22/tcp]  ● OPEN  Risk: ███░░░░░░░ 35/100 [LOW]  ⚠ PROTECTED

  > Close (permanent + runtime)
    Open only for IP/CIDR (Rich Rule)
    Risk assessment
    Service details
    Back

  [↑↓] Navigate  [Enter] Select  [Esc] Cancel
```

**Options:**
- **Open / Close** — permanent + runtime (survives reboot)
- **Open runtime only** — active until the next `firewall-cmd --reload`
- **Open only for IP/CIDR** — adds a rich rule restricting access to one source address
- **Risk assessment** — full explanation of the port's security profile
- **Service details** — ports, description, risk score

### Risk Column

Every service shows a risk bar in the list:

| Colour | Label | Score | Meaning |
|--------|-------|-------|---------|
| 🟢 Green | MINIMAL | 0–19 | Standard protocol, well-audited, encrypted |
| 🔵 Cyan | LOW | 20–44 | Minor risks, usually fine if configured correctly |
| 🟡 Yellow | MEDIUM | 45–69 | Notable attack surface, check your configuration |
| 🟠 Orange | HIGH | 70–89 | Significant exploitation history, restrict access |
| 🔴 Red | CRITICAL | 90–100 | Direct path to system compromise — do not expose publicly |

---

## CLI — Direct Commands

All commands work without starting the TUI. Useful for scripts and automation.

### `status` — Show open ports with risk scores

```bash
firewall-manager status
firewall-manager -z dmz status     # specific zone
```

Output includes a table of open services with their ports, a colour-coded risk bar, and a one-line risk summary.

### `list` — Short list of open services/ports

```bash
firewall-manager list
```

### `open` — Open a port or service

```bash
firewall-manager open https           # by service name
firewall-manager open 8080/tcp        # by port/protocol
firewall-manager open 8080/tcp --runtime-only   # until next reload only
firewall-manager open 8080/tcp -z dmz           # specific zone
```

Changes are permanent + runtime by default. `--runtime-only` skips writing to the permanent config.

### `close` — Close a port or service

```bash
firewall-manager close 8080/tcp
firewall-manager close http
```

Closing `ssh` or `https` triggers an extra confirmation prompt.

### `lockdown` — Close everything except SSH and HTTPS

```bash
firewall-manager lockdown             # interactive confirmation
firewall-manager lockdown --dry-run   # preview only, no changes
firewall-manager lockdown --yes       # skip confirmation (for scripts)
firewall-manager lockdown --keep ssh,https,http  # custom keep list
firewall-manager lockdown -z internal            # specific zone
```

Removes all open services and raw port rules from the zone except the ones in `--keep`. Changes are permanent + runtime.

### `risk` — Detailed risk assessment

```bash
firewall-manager risk telnet
firewall-manager risk 3389/tcp
firewall-manager risk redis
firewall-manager risk 6379/tcp
```

```
╭─────────────────────────────  Risk Assessment  ──────────────────────────────╮
│ Target: telnet (23/tcp)                                                      │
│ Score:  █████████████████████████████░ 98/100  CRITICAL                      │
│ Summary: Telnet – cleartext, no encryption, trivially sniffable              │
╰──────────────────────────────────────────────────────────────────────────────╯

Explanation:
  Telnet transmits all data, including passwords, in cleartext. Any network
  observer can capture credentials and gain full shell access. There are no
  modern use cases that justify exposing Telnet publicly. Replace with SSH
  (port 22) immediately. Historically used for initial router/switch access;
  frequently exploited by Mirai and similar botnets.

Notable CVEs: CVE-2020-10188, CVE-2011-4862
```

---

## Risk Database

The built-in risk database covers 77 port/protocol combinations with scores, summaries, detailed explanations, and notable CVEs. A selection:

| Port | Score | Label | Why |
|------|-------|-------|-----|
| `23/tcp` Telnet | **98** | CRITICAL | Cleartext credentials, no encryption |
| `2375/tcp` Docker API | **98** | CRITICAL | Unauthenticated container escape to root |
| `3389/tcp` RDP | **93** | CRITICAL | BlueKeep (CVE-2019-0708), constant ransomware target |
| `445/tcp` SMB | **92** | CRITICAL | EternalBlue/WannaCry (CVE-2017-0144) |
| `11211/udp` Memcached | **90** | CRITICAL | 51,000× DDoS amplification factor |
| `4444/tcp` | **90** | CRITICAL | Metasploit default shell — strong indicator of compromise |
| `9200/tcp` Elasticsearch | **87** | HIGH | No auth by default, billions of records exposed |
| `27017/tcp` MongoDB | **86** | HIGH | No auth by default, automated wipe attacks |
| `6379/tcp` Redis | **88** | HIGH | No auth, write SSH keys, RCE via cron |
| `5900/tcp` VNC | **85** | HIGH | Often unencrypted, weak/no auth |
| `3306/tcp` MySQL | **78** | HIGH | Credential attacks, file read via SELECT INTO OUTFILE |
| `631/udp` CUPS browsed | **62** | MEDIUM | Entry point for 2024 RCE chain (CVE-2024-47176) |
| `22/tcp` SSH | **35** | LOW | Encrypted, but brute-forced constantly — use key auth |
| `443/tcp` HTTPS | **15** | MINIMAL | Encrypted; risk is from the web app, not the port |
| `51820/udp` WireGuard | **12** | MINIMAL | Modern VPN, stealth by default, excellent crypto |

Ports not in the database get a default score based on their range (privileged <1024, registered 1024–49151, ephemeral >49151).

---

## Project Structure

```
firewalld-manager/
├── firewalld_manager/
│   ├── __init__.py
│   ├── cli.py           # Click CLI entry point
│   ├── firewall.py      # FirewallManager — wraps python-firewall D-Bus API
│   ├── risk.py          # Port risk database (77 entries, scores 0–100)
│   └── tui/
│       ├── __init__.py
│       ├── app.py       # Main prompt_toolkit full-screen application
│       ├── port_list.py # Filterable/scrollable service list component
│       └── dialogs.py   # Async dialogs: confirm, action menu, lockdown, rich rule
└── pyproject.toml
```

**Key design decisions:**
- Uses the `python-firewall` D-Bus API directly — no `subprocess`/`firewall-cmd` calls
- All TUI dialogs are `async` — they run inside the existing prompt_toolkit event loop without spawning a new one
- Permanent + runtime is the default for all changes (runtime-only is opt-in)
- SSH and HTTPS are always flagged as protected; extra confirmation is required to close them

---

## How firewalld Zones Work

firewalld organises rules into **zones**. Each zone has a trust level and a set of open services/ports. A network interface (e.g. `wlp58s0`) is assigned to exactly one zone.

Common zones:

| Zone | Default trust |
|------|--------------|
| `public` | Low — only explicitly opened services are allowed |
| `home` | Medium — more services allowed by default |
| `internal` | High — trusted internal network |
| `dmz` | Low — only selected inbound services |
| `drop` | None — all inbound traffic dropped silently |
| `block` | None — all inbound traffic rejected with ICMP |

`firewall-manager` defaults to the active zone of your primary interface. Use `-z <zone>` to target a different zone.
