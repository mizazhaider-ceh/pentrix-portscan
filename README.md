# pentrix-portscan

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#install)

Fast async TCP port scanner with banner grabbing and service hints. Pure Python standard library, no pip packages needed.

## Features

- **Fast**: asyncio with semaphore-limited concurrency (default 300 simultaneous connections). Scans 500 ports on localhost in about 1 second.
- **Banner grabbing** (`--banner`): passively reads up to 1024 bytes from open ports, and sends a `HEAD` probe on common HTTP ports to pull real server headers. Non-printable characters are stripped and long banners are truncated.
- **Service hints**: built-in mapping of common ports to service names (ssh, http, smb, mysql, redis, rdp, ...).
- **Flexible port selection**: single ports (`80,443`), ranges (`1-1000`), or the built-in `top100` list. Mix them freely.
- **Clean output**: readable console report plus optional `-o` file output.
- **Sensible errors**: clear messages for unresolvable hosts and invalid port specs, with documented exit codes.

## Install

```bash
git clone https://github.com/mizazhaider-ceh/pentrix-portscan.git
cd pentrix-portscan
python3 portscan.py --help
```

Requirements: Python 3.8 or newer. Zero dependencies, standard library only (`asyncio`, `argparse`, `socket`).

## Usage

Scan the top 100 most common ports on a target:

```bash
python3 portscan.py 192.168.1.10
```

Scan specific ports with banner grabbing and save the report:

```bash
python3 portscan.py 127.0.0.1 -p 7995-8005 --banner --timeout 0.5 -o scan.txt
```

```
Scanning 127.0.0.1 (127.0.0.1): 11 port(s), timeout 0.5s, banner grabbing on

pentrix-portscan report for 127.0.0.1 (127.0.0.1)
Open ports: 1 of 11 scanned in 0.01s

PORT       SERVICE        BANNER
8000/tcp   http-alt       HTTP/1.0 200 OK / Server: SimpleHTTP/0.6 Python/3.12.3 / Date: Fri, 02 Oct 2026 11:30:48 GMT

Report written to scan.txt
```

(The test target above was a local `python3 -m http.server 8000 --bind 127.0.0.1`. The scanner detected the open port and the `HEAD` probe pulled the real `Server:` header.)

Scan a wide range quickly (closed ports are cheap):

```bash
python3 portscan.py 127.0.0.1 -p 1-500 --timeout 0.5
```

```
Scanning 127.0.0.1 (127.0.0.1): 500 port(s), timeout 0.5s

pentrix-portscan report for 127.0.0.1 (127.0.0.1)
Open ports: 0 of 500 scanned in 1.07s

No open ports found.
```

Mix port selections:

```bash
python3 portscan.py example.com -p 22,80,443,8000-8100,top100 --banner
```

### Options

```
usage: portscan.py [-h] [-p PORTS] [--timeout SECONDS] [--banner] [-c N]
                   [-o FILE]
                   target

positional arguments:
  target                Target host: IP address or hostname.

options:
  -p PORTS, --ports PORTS
                        Ports to scan. Comma separated mix of single ports
                        ("80,443"), ranges ("1-1000") and the "top100"
                        selection. Default: top100.
  --timeout SECONDS     Connect timeout per port in seconds. Default: 1.0.
  --banner              Grab service banners from open ports (sends a HEAD
                        probe on common HTTP ports, otherwise just reads).
  -c N, --concurrency N
                        Max simultaneous connections. Default: 300.
  -o FILE, --output FILE
                        Write the scan report to FILE as well as printing it.

Exit codes: 0 scan completed, 1 runtime error, 2 bad arguments.
```

## Ethical use

Only scan hosts you own or are explicitly authorized to test. Unauthorized port scanning can violate computer misuse laws and the terms of service of networks you do not control. This tool is for learning, lab work, and authorized security testing.

## License

MIT. See [LICENSE](LICENSE).
