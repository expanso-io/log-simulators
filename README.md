# log-simulators

Realistic log generators for testing data pipelines at volume. Ten simulators
covering the device types that matter for SIEM and observability pipelines —
each one a single command that needs **only [uv](https://docs.astral.sh/uv/)**.

```bash
uvx --from git+https://github.com/expanso-io/log-simulators logsim-web --rate 100
```

No clone, no install, no Docker. Pipe the output anywhere — a file, a TCP/UDP
collector, or straight into an [Expanso Edge](https://expanso.io) pipeline.

## The simulators

| Tool | Generates | Demo scenario |
|------|-----------|---------------|
| `logsim-web` | Apache/nginx access + error logs (NCSA combined/common/JSON), session-coherent visitors | `error-storm` — recurring 5xx spikes |
| `logsim-iot` | IoT sensor telemetry NDJSON: temperature, humidity, pressure, vibration, voltage with drift + diurnal cycles | `sensor-fault` — spikes, stuck values, dropouts |
| `logsim-syslog` | RFC 3164 and RFC 5424 syslog with realistic facility/severity mix | `auth-burst` — failed-login floods |
| `logsim-windows` | Windows Security Event XML (4624/4625/4688/4672) | `brute-force` — 4625 password-spray bursts |
| `logsim-asa` | Cisco ASA firewall syslog — paired build/teardown with consistent connection IDs, denies | `port-scan` — deny storms from one source |
| `logsim-cef` | CEF and LEEF security events (firewall/IPS style) | `malware-burst` — high-severity event waves |
| `logsim-app` | Structured JSON app logs with trace IDs and realistic embedded PII (for redaction demos) | `error-storm`, `pii-leak` |
| `logsim-cloud` | AWS CloudTrail JSON and VPC Flow Logs | `suspicious-login` — off-region console logins |
| `logsim-k8s` | Kubernetes CRI container logs — multi-pod node, klog + JSON apps, partial-line mechanics | `crash-loop` — restarting pod |
| `logsim-postgres` | PostgreSQL server logs incl. multiline ERROR/DETAIL/STATEMENT and slow queries | `deadlock` — lock-contention windows |

Every tool shares the same CLI contract:

```text
--rate N            average events/sec (Poisson-paced, like real traffic)
--count N           stop after N events (0 = run forever)
--duration 5m       stop after a wall-clock duration
--backfill 24h      synthesize 24h of history at full speed, then exit
--follow            ...then keep streaming live
--start-time ISO    anchor the backfill window (deterministic with --seed)
--seed N            fully reproducible output
--diurnal           overnight trough, midday peak
--output DEST       '-' stdout (default) | file path | tcp://host:port | udp://host:port
--rotate-mb N       rotate + gzip file output
--scenario NAME     inject recurring anomaly windows (per-tool)
```

## Quick start

```bash
# Stream Apache combined logs at 50/sec forever
uvx --from git+https://github.com/expanso-io/log-simulators logsim-web --rate 50

# 24 hours of historical IoT telemetry, then exit
uvx --from git+https://github.com/expanso-io/log-simulators logsim-iot --backfill 24h --output sensors.ndjson

# A brute-force attack inside normal Windows event noise, to a UDP collector
uvx --from git+https://github.com/expanso-io/log-simulators logsim-windows \
    --scenario brute-force --rate 20 --output udp://localhost:5514

# Reproducible test fixture: same command, byte-identical output
uvx --from git+https://github.com/expanso-io/log-simulators logsim-asa \
    --seed 42 --count 1000 --backfill 1h --start-time 2026-01-15T12:00:00+00:00

# Umbrella command works too
uvx --from git+https://github.com/expanso-io/log-simulators logsim k8s --rate 30
```

Single-file versions of the most-used tools live in [`standalone/`](standalone/) —
each is a self-contained [PEP 723](https://peps.python.org/pep-0723/) script:

```bash
uv run https://raw.githubusercontent.com/expanso-io/log-simulators/main/standalone/web_access_sim.py --rate 10
```

## Why these formats

The May 2025 joint CISA/NSA/ACSC guidance,
[*Priority logs for SIEM ingestion*](https://media.defense.gov/2025/May/27/2003722069/-1/-1/0/Priority-logs-for-SIEM-ingestion-Practitioner-guidance.PDF),
names the sources practitioners should prioritize: OS logs, network devices,
firewalls/IDS, and cloud audit trails — and explicitly recommends *against*
shipping everything raw into the SIEM. This suite generates exactly those
sources, so you can build and demo the filtering/routing layer in front of
the SIEM with realistic volume, then prove zero-loss delivery (seeded,
countable output) end to end.

What makes the output realistic rather than random:

- **Entity consistency** — the same hosts, users, IPs, and devices recur
  coherently (a firewall's teardown matches its build; a session keeps its IP).
- **Skewed distributions** — Zipf popularity for paths/IPs, long-tail response
  sizes, Poisson inter-arrival times.
- **Scenario injection** — a baseline of boring traffic with deterministic,
  recurring anomaly windows you can catch in a pipeline.
- **Seeded determinism** — `--seed` + `--start-time` reproduce byte-identical
  streams for tests and fixtures.

## Development

```bash
git clone https://github.com/expanso-io/log-simulators
cd log-simulators
uv sync            # installs everything incl. dev tools
uv run pytest      # full test suite
uv run ruff check . && uv run ruff format --check .
uv run logsim list # see all tools
```

The layout is a single distribution with one subpackage per simulator plus a
shared core (`src/log_simulators/core/`) providing pacing, sinks, entity
pools, and scenario scheduling. This keeps
`uvx --from git+...` working verbatim — a multi-package workspace would not
survive git installation (see uv issues
[#16328](https://github.com/astral-sh/uv/issues/16328) /
[#10728](https://github.com/astral-sh/uv/issues/10728)).

## Lineage

Aggregates and supersedes
[bacalhau-project/access-log-generator](https://github.com/bacalhau-project/access-log-generator),
[bacalhau-project/sensor-log-generator](https://github.com/bacalhau-project/sensor-log-generator),
and several smaller internal generators. CLI ergonomics inspired by
[mingrammer/flog](https://github.com/mingrammer/flog).

## License

Apache-2.0
