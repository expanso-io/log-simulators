"""Umbrella `logsim` command: dispatches to the individual simulators.

`logsim web --rate 50` is equivalent to `logsim-web --rate 50`.
"""

from __future__ import annotations

import importlib
import sys

from . import __version__

TOOLS: dict[str, str] = {
    "web": "Apache/nginx access and error logs (sessions, diurnal traffic)",
    "iot": "IoT sensor telemetry NDJSON (drift, anomalies, device fleet)",
    "syslog": "RFC 3164 / RFC 5424 syslog",
    "windows": "Windows Security Event Log XML (4624/4625/4688/4672)",
    "asa": "Cisco ASA firewall syslog (build/teardown/deny)",
    "cef": "CEF and LEEF security events (firewall/IPS)",
    "app": "structured JSON application logs (trace IDs, PII fields)",
    "cloud": "AWS CloudTrail JSON and VPC Flow Logs",
    "k8s": "Kubernetes CRI container logs (klog + JSON apps)",
    "postgres": "PostgreSQL server logs (multiline ERROR/DETAIL/STATEMENT)",
    "vmware": "VMware vSphere logs (vCenter tasks + ESXi vmkernel/hostd)",
    "ics": "Industrial/OT network-device syslog (Cisco-IOS-style, PLC comms)",
    "retail": "Retail point-of-sale transactions (CSV or JSON, structured)",
}


def _usage() -> str:
    lines = [
        f"logsim {__version__} - realistic log generators (Expanso)",
        "",
        "usage: logsim <tool> [options]   (each tool also exists as logsim-<tool>)",
        "",
        "tools:",
    ]
    lines += [f"  {name:<10} {desc}" for name, desc in TOOLS.items()]
    lines += ["", "run `logsim <tool> --help` for tool options"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in ("-h", "--help", "help", "list"):
        print(_usage())
        return 0
    if args[0] in ("-V", "--version"):
        print(__version__)
        return 0
    tool = args[0]
    if tool not in TOOLS:
        print(f"logsim: unknown tool {tool!r}\n\n{_usage()}", file=sys.stderr)
        return 2
    module = importlib.import_module(f"log_simulators.{tool}.cli")
    result = module.main(args[1:])
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
