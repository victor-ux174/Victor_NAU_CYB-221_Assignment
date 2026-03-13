# Victor_NAU_CYB-221_Assignment
Name: Ubah Victor ikechukwu 

Registration Number: 2024924044

Course Code: NAU-CYB 221

Level: 200l

Department: Cyber Security

Faculty: Physical Science

```markdown
# NAU-CYB 221 – Local Listening Ports Scanner  
**Defensive – Local Machine Only**  
**Modern Linux Implementation (ss-based)**

```
Obi Promise Uche  
Registration Number: 2024924028  
Course Code: NAU-CYB 221  
Level: 200 Level  
Department: Cyber Security  
Faculty: Physical Science  
NAU-CYB 221 – Cybersecurity Technology Practical Assignment
```

## Project Description

This is a clean, reliable **C++ local port inspection tool** designed for defensive cybersecurity analysis on Linux systems.

Instead of manually parsing the complex `/proc/net/tcp` and `/proc/net/udp` files (with hex addresses and inode lookups), this version uses the standard **iproute2** utility:

```bash
ss -ltnup
```

→ **Why this is better**:
- Shows **only listening ports** (`-l`)
- Correctly identifies owning process and PID (with sudo)
- Handles both IPv4 and IPv6 automatically
- No fragile hex parsing or slow `/proc/*/fd` walking
- Produces accurate, production-grade results

### Features

- Lists only **listening** TCP/UDP sockets  
- Shows: protocol, port, local address, PID, process name, service (from `/etc/services`), risk level, security flag, TCP state  
- Classifies bindings as **Local-only** (127.0.0.1 / ::1) or **Exposed**  
- Flags well-known sensitive ports (FTP, SSH, HTTP, SMB, RDP, databases…)  
- Clean aligned terminal table  
- Saves results to `ports_report.txt` and `ports_report.json`  
- Shows top 5 ports by security concern

## Requirements

- Linux system (tested on ChromeOS Crostini – Debian container)  
- `iproute2` package installed (`ss` command)  
  → usually already present; if not: `sudo apt install iproute2`  
- g++ compiler with C++11 support  
- Run with **sudo** to see process names and PIDs

## Build Instructions

```bash
# Compile
g++ -o port_inspector port_inspector.cpp -std=c++11 -Wall -O2

# Or with warnings & optimization
g++ -o port_inspector port_inspector.cpp -std=c++11 -Wall -Wextra -O2
```

## Usage

```bash
# Basic run (shows ports – but no process info without sudo)
./port_inspector

# Recommended – full visibility (PID & process names)
sudo ./port_inspector
```

## Sample Output (ChromeOS Crostini – sudo run – March 2026)

```
NAU-CYB 221 Local Port Scanner (ss-based version)
Running with sudo recommended for full process visibility

=== Local Listening Ports Report – 2026-03-13 23:06:13 ===

Proto  Port    Local Address      PID   Process  Service  Risk       Flag         State
---------------------------------------------------------------------------------------------------------
TCP    5036    127.0.0.1          783   code     —        Local-only Normal       LISTEN
TCP    45017   127.0.0.1          584   code     —        Local-only Normal       LISTEN

Reports saved:
   • ports_report.txt
   • ports_report.json

Top 5 ports by security concern:
TCP 5036 (—) – Local-only / Normal → code (PID 783)
TCP 45017 (—) – Local-only / Normal → code (PID 584)
```

**Interpretation (real result from this run):**
- Only **two loopback-bound TCP ports**  
- Both owned by **Visual Studio Code** (`code` process)  
- No UDP ports in listening state  
- No ports bound to `0.0.0.0` or external interfaces  
- Extremely small and safe attack surface

## Current Limitations

- Requires `sudo` for process name / PID visibility  
- Depends on `ss` being installed and working  
- Service names missing for non-standard / high ports  
- No command-line arguments yet (e.g. `--json-only`, `--tcp-only`, `--port 80`)  
- Output is focused on listening sockets only (good for defense)

## Future Improvements (optional student extensions)

- Add command-line flags using `getopt` or a simple parser  
- Add IPv6-specific filtering or display  
- Colorize output (green = local-only, red = exposed/high-interest)  
- Filter by port range or protocol  
- Compare snapshots over time to detect new listeners

## Security & Educational Context

This tool was created as part of **NAU-CYB 221** coursework to:

- Understand local network exposure on Linux  
- Practice defensive system reconnaissance  
- Recognize safe vs. risky port bindings  
- Compare raw `/proc` parsing vs. using mature system tools

**Key takeaway from this run:**  
Modern container environments like Crostini (ChromeOS Linux) + minimal development setups can achieve near-zero external attack surface by default — only loopback development ports remain when actively coding.

**Author:** Ubah Victor ikechukwu  
**Course:** NAU-CYB 221 – Cybersecurity Technology  
**Date:** March 2026
