#!/usr/bin/env python3
"""pentrix-portscan: fast async TCP port scanner with banner grabbing.

Scans TCP ports on a target host using asyncio, reports open ports with a
service hint and an optional banner grab. Standard library only.
"""

import argparse
import asyncio
import socket
import sys
import time

DEFAULT_TIMEOUT = 1.0
DEFAULT_CONCURRENCY = 300
BANNER_READ_BYTES = 1024
BANNER_TIMEOUT = 2.0
BANNER_PREVIEW_LEN = 200

# Common TCP ports mapped to a service hint.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 464: "kpasswd", 465: "smtps", 512: "exec",
    513: "login", 514: "syslog", 515: "printer", 548: "afp",
    554: "rtsp", 587: "submission", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1099: "rmiregistry",
    1194: "openvpn", 1433: "mssql", 1434: "mssql-monitor",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt",
    3306: "mysql", 33060: "mysqlx", 3389: "rdp", 3690: "svn",
    4369: "epmd", 4848: "glassfish", 5000: "http-alt",
    5060: "sip", 5061: "sips", 5432: "postgres", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
    6000: "x11", 6379: "redis", 6667: "irc", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp", 8080: "http-alt", 8081: "http-alt",
    8089: "splunk", 8090: "http-alt", 8443: "https-alt",
    8888: "http-alt", 8889: "http-alt", 9000: "http-alt",
    9090: "http-alt", 9092: "kafka", 9200: "elasticsearch",
    10000: "webmin", 10050: "zabbix-agent", 10051: "zabbix-server",
    11211: "memcached", 15672: "rabbitmq-mgmt",
    27015: "source-engine", 27017: "mongodb", 25565: "minecraft",
    19132: "minecraft-bedrock",
}

# Ports that usually speak plain HTTP, so a HEAD probe is worth trying.
HTTP_PORTS = {
    80, 3000, 5000, 7001, 7777, 8000, 8008, 8080, 8081,
    8090, 8888, 8889, 9000, 9090, 10000,
}

# Frequently open ports, used by the "top100" port selection.
TOP100 = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 554, 26,
    1433, 49152, 2001, 515, 8008, 49154, 1027, 191, 512, 513,
    1028, 1935, 444, 1080, 3128, 4444, 5555, 6667, 5432, 6379,
    27017, 11211, 9200, 5985, 4786, 4848, 7001, 7070, 7777, 8880,
    9000, 9090, 5000, 3000, 2375, 2376, 5044, 5601, 8009, 8081,
    8090, 8889, 9999, 27015, 25565, 19132, 33060, 1434, 161, 69,
    123, 389, 636, 88, 464, 3268, 3269, 5988, 5989, 6514,
]


def parse_ports(spec):
    """Parse a port specification into a sorted list of unique ports.

    Accepts comma separated items where each item is one of:
      - a single port:        "80"
      - a range:              "1-1000"
      - a top-N selection:    "top100"
    Raises ValueError on anything invalid.
    """
    ports = set()
    for item in spec.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if item.startswith("top"):
            count = item[3:]
            if count == "100":
                ports.update(TOP100)
            else:
                raise ValueError(
                    "unsupported top-N selection %r (only top100 is supported)" % item
                )
            continue
        if "-" in item:
            parts = item.split("-", 1)
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError("invalid port range %r" % item)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(
                    "port range %r out of bounds (valid: 1-65535)" % item
                )
            ports.update(range(start, end + 1))
            continue
        try:
            port = int(item)
        except ValueError:
            raise ValueError("invalid port %r" % item)
        if port < 1 or port > 65535:
            raise ValueError("port %d out of bounds (valid: 1-65535)" % port)
        ports.add(port)
    if not ports:
        raise ValueError("no ports selected")
    return sorted(ports)


def clean_banner(raw):
    """Turn raw banner bytes into a short, printable, single-line preview."""
    text = raw.decode("utf-8", errors="replace")
    text = "".join(ch for ch in text if ch.isprintable() or ch == "\n")
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    preview = " / ".join(lines[:3])
    if len(preview) > BANNER_PREVIEW_LEN:
        preview = preview[:BANNER_PREVIEW_LEN] + "..."
    return preview


async def grab_banner(reader, writer, port, timeout):
    """Read a service banner, optionally sending a HEAD probe on HTTP ports."""
    try:
        if port in HTTP_PORTS:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
        data = await asyncio.wait_for(
            reader.read(BANNER_READ_BYTES), timeout=timeout
        )
        return clean_banner(data) if data else ""
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return ""


async def scan_port(host, port, timeout, grab, semaphore):
    """Try to connect to one port. Returns (port, open, banner)."""
    async with semaphore:
        reader = writer = None
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return (port, False, "")
        banner = ""
        if grab:
            banner_timeout = max(timeout, BANNER_TIMEOUT)
            banner = await grab_banner(reader, writer, port, banner_timeout)
        try:
            writer.close()
            await writer.wait_closed()
        except (OSError, AttributeError):
            pass
        return (port, True, banner)


def resolve_target(target):
    """Resolve a hostname to an IP address. Raises socket.gaierror on failure."""
    infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    return infos[0][4][0]


def format_results(target, ip, results, elapsed):
    """Build the human readable scan report."""
    lines = []
    lines.append("pentrix-portscan report for %s (%s)" % (target, ip))
    open_results = [(p, b) for (p, is_open, b) in results if is_open]
    lines.append("Open ports: %d of %d scanned in %.2fs"
                 % (len(open_results), len(results), elapsed))
    lines.append("")
    if open_results:
        lines.append("%-10s %-14s %s" % ("PORT", "SERVICE", "BANNER"))
        for port, banner in open_results:
            service = COMMON_PORTS.get(port, "unknown")
            lines.append("%-10s %-14s %s" % ("%d/tcp" % port, service, banner))
    else:
        lines.append("No open ports found.")
    return "\n".join(lines)


async def run_scan(target, ip, ports, timeout, grab, concurrency):
    """Scan all ports concurrently and return a list of (port, open, banner)."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        scan_port(ip, port, timeout, grab, semaphore) for port in ports
    ]
    results = []
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)
    results.sort(key=lambda r: r[0])
    return results


def build_parser():
    parser = argparse.ArgumentParser(
        prog="portscan.py",
        description=(
            "Fast async TCP port scanner with banner grabbing and service hints. "
            "Only scan hosts you own or are explicitly authorized to test."
        ),
        epilog=(
            "Port selection examples:\n"
            "  portscan.py 192.168.1.10 -p 80,443\n"
            "  portscan.py example.com -p 1-1000 --banner\n"
            "  portscan.py 10.0.0.5 -p top100 -o results.txt\n"
            "\nExit codes: 0 scan completed, 1 runtime error, "
            "2 bad arguments."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        help="Target host: IP address or hostname (e.g. 192.168.1.10 or example.com).",
    )
    parser.add_argument(
        "-p", "--ports",
        default="top100",
        help=(
            'Ports to scan. Comma separated mix of single ports ("80,443"), '
            'ranges ("1-1000") and the "top100" selection. '
            "Default: top100."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help="Connect timeout per port in seconds. Default: %(default)s.",
    )
    parser.add_argument(
        "--banner",
        action="store_true",
        help=(
            "Grab service banners from open ports (sends a HEAD probe on "
            "common HTTP ports, otherwise just reads)."
        ),
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        metavar="N",
        help="Max simultaneous connections. Default: %(default)s.",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write the scan report to FILE as well as printing it.",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")

    try:
        ip = resolve_target(args.target)
    except socket.gaierror:
        print("error: could not resolve host %r" % args.target, file=sys.stderr)
        return 1

    print("Scanning %s (%s): %d port(s), timeout %.1fs%s"
          % (args.target, ip, len(ports), args.timeout,
             ", banner grabbing on" if args.banner else ""))

    start = time.monotonic()
    try:
        results = asyncio.run(
            run_scan(args.target, ip, ports, args.timeout, args.banner,
                     args.concurrency)
        )
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - start

    report = format_results(args.target, ip, results, elapsed)
    print()
    print(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
            print("\nReport written to %s" % args.output)
        except OSError as exc:
            print("error: could not write to %r: %s" % (args.output, exc),
                  file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
