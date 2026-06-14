"""Tests for logsim-vmware (VMware vSphere: vCenter vpxd + ESXi host syslog)."""

from __future__ import annotations

import re
from collections import Counter

from log_simulators.vmware.cli import CONNECTIVITY_SENSE, main

from .conftest import generate

FACILITY = 16  # local0: the single facility both planes forward on
TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(?:Z|[+-]\d{2}:\d{2})"

# vCenter (vpxd) RFC 5424 envelope; groups: PRI, sub, opID, body.
VC_RE = re.compile(
    rf"^<(\d{{1,3}})>1 {TS} vcenter-\d+\.corp\.example\.com vpxd \d+ - - "
    rf"\[Originator@6876 sub=(\S+) opID=(\S+)\] (.+)$"
)
# ESXi host RFC 5424 envelope; groups: PRI, host-short, app, body.
ESXI_RE = re.compile(
    rf"^<(\d{{1,3}})>1 {TS} (esx-host-\d+)\.corp\.example\.com "
    rf"(vmkernel|hostd|vpxa|vobd) - - - (.+)$"
)

# vpxd LRO task bodies; groups: task id, moref, method, (uuid|result).
BEGIN_RE = re.compile(
    r"^\[VpxLRO\] -- BEGIN (task-\d+) -- (vm-\d+) -- (vim\.\w+\.\w+) -- [0-9a-f-]{20,}$"
)
FINISH_RE = re.compile(
    r"^\[VpxLRO\] -- FINISH (task-\d+) -- (vm-\d+) -- (vim\.\w+\.\w+) -- (success|error)$"
)

VMK_RE = re.compile(r"^cpu\d+:\d+\)[A-Za-z0-9_]+: \d+: .+$")
# Greedy: capture the whole device id so length is validated, not just a prefix.
NAA_RE = re.compile(r"naa\.[0-9a-f]+")
# Real VMware NAA Type-6 (IEEE Registered Extended, 128-bit) ids are 32 hex digits:
# the 'naa.6006016' prefix (7 hex) plus a 25-hex tail.
NAA_TYPE6_RE = re.compile(r"^naa\.6006016[0-9a-f]{25}$")
STORAGE_ERR = "failed H:0x"  # vmkernel ScsiDeviceIO failure signature
# The SCSI sense tail of a storage-error line; group 1 is the H/D/P + sense tuple,
# byte-identical to an entry in CONNECTIVITY_SENSE / GENERIC_SENSE.
SENSE_RE = re.compile(
    r"failed (H:0x[0-9a-f]+ D:0x[0-9a-f]+ P:0x[0-9a-f]+ "
    r"(?:Valid|Possible) sense data: 0x[0-9a-f]+ 0x[0-9a-f]+ 0x[0-9a-f]+)$"
)
HA_RESTART = "vSphere HA restarted virtual machine"
HOST_CONN_ALARM = "Alarm 'Host connection and power state'"
DISP_MOREF_RE = re.compile(r"([a-z][a-z0-9-]*-\d+) \((vm-\d+)\)")


def _pri(line: str) -> int:
    m = re.match(r"<(\d+)>", line)
    assert m, line
    return int(m.group(1))


class TestFormats:
    def test_vcenter_lines_full_match(self) -> None:
        for line in generate(main, count=400, extra=["--format", "vcenter"]):
            m = VC_RE.match(line)
            assert m, line
            assert _pri(line) // 8 == FACILITY  # single forwarding facility
            body = m.group(4)
            assert (
                BEGIN_RE.match(body)
                or FINISH_RE.match(body)
                or body.startswith(("User ", "DRS-recommended ", "Alarm '", "vSphere HA "))
            ), line

    def test_esxi_lines_full_match(self) -> None:
        for line in generate(main, count=400, extra=["--format", "esxi"]):
            m = ESXI_RE.match(line)
            assert m, line
            assert _pri(line) // 8 == FACILITY
            app, body = m.group(3), m.group(4)
            if app == "vmkernel":
                assert VMK_RE.match(body), line
            elif app == "hostd":
                assert body.startswith("Event "), line

    def test_both_emits_a_coherent_mix_of_both_planes(self) -> None:
        kinds = Counter(
            "vcenter" if VC_RE.match(line) else "esxi" if ESXI_RE.match(line) else "?"
            for line in generate(main, count=600, extra=["--format", "both"])
        )
        assert kinds["?"] == 0  # every line matched one plane
        assert kinds["vcenter"] > 40
        assert kinds["esxi"] > 40

    def test_default_format_is_both(self) -> None:
        kinds = {
            "vcenter" if VC_RE.match(line) else "esxi" if ESXI_RE.match(line) else "?"
            for line in generate(main, count=400)
        }
        assert kinds == {"vcenter", "esxi"}

    def test_pri_severity_in_range(self) -> None:
        for line in generate(main, count=500):
            prival = _pri(line)
            assert 0 <= prival <= 191
            assert 0 <= prival % 8 <= 7


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=120) == generate(main, count=120)

    def test_same_seed_same_output_vcenter(self) -> None:
        extra = ["--format", "vcenter"]
        assert generate(main, count=120, extra=extra) == generate(main, count=120, extra=extra)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=120, seed=1) != generate(main, count=120, seed=2)


class TestTaskPairing:
    def test_every_finish_was_begun_with_matching_id_method_and_opid(self) -> None:
        begun: dict[str, tuple[str, str, str]] = {}  # task -> (moref, method, opID)
        finishes = orphans = 0
        for line in generate(main, count=4000, extra=["--format", "vcenter"]):
            m = VC_RE.match(line)
            assert m, line
            op, body = m.group(3), m.group(4)
            if b := BEGIN_RE.match(body):
                begun[b.group(1)] = (b.group(2), b.group(3), op)
            elif f := FINISH_RE.match(body):
                finishes += 1
                prev = begun.pop(f.group(1), None)
                if prev is None:
                    orphans += 1
                    continue
                moref, method, begin_op = prev
                assert (f.group(2), f.group(3)) == (moref, method), line  # estate stable
                assert op == begin_op, line  # opID shared across the pair
        assert finishes > 100
        assert orphans == 0  # no FINISH without a prior BEGIN
        assert len(begun) <= 64  # open backlog bounded by MAX_OPEN_TASKS

    def test_finish_result_agrees_with_severity(self) -> None:
        ok = err = 0
        for line in generate(main, count=4000, extra=["--format", "vcenter"]):
            m = VC_RE.match(line)
            if not m or not (f := FINISH_RE.match(m.group(4))):
                continue
            if f.group(4) == "success":
                assert _pri(line) % 8 == 6, line  # info
                ok += 1
            else:
                assert _pri(line) % 8 == 3, line  # err
                err += 1
        assert ok > 50
        assert err > 5  # ~12% of tasks fail


class TestRealism:
    def test_naa_device_ids_well_formed(self) -> None:
        seen = 0
        for line in generate(main, count=2000, extra=["--format", "esxi"]):
            for m in NAA_RE.finditer(line):
                seen += 1
                naa = m.group(0)
                # NAA Type-6: 'naa.' + exactly 32 hex digits (not the old 16).
                assert NAA_TYPE6_RE.match(naa), line
                assert len(naa) == len("naa.") + 32, line
        assert seen > 20

    def test_vm_moref_maps_to_one_stable_display_name(self) -> None:
        moref_to_disp: dict[str, str] = {}
        for line in generate(main, count=3000):
            for m in DISP_MOREF_RE.finditer(line):
                disp, moref = m.group(1), m.group(2)
                assert moref_to_disp.setdefault(moref, disp) == disp, line
        assert len(moref_to_disp) > 5

    def test_esxi_hosts_recur_from_small_skewed_pool(self) -> None:
        hosts = Counter(
            m.group(2)
            for line in generate(main, count=1500, extra=["--format", "esxi"])
            if (m := ESXI_RE.match(line))
        )
        assert 6 <= len(hosts) <= 8  # estate is 6-8 ESXi hosts
        assert hosts.most_common(1)[0][1] > 1500 * 0.10  # zipf-skewed, not uniform

    def test_task_verbs_are_real_vim_methods(self) -> None:
        verbs: Counter[str] = Counter()
        for line in generate(main, count=2000, extra=["--format", "vcenter"]):
            m = VC_RE.match(line)
            if m and (b := BEGIN_RE.match(m.group(4))):
                verbs[b.group(3)] += 1
        assert verbs
        for method in verbs:
            assert method.startswith("vim.VirtualMachine.")
        assert verbs.most_common(1)[0][0] == "vim.VirtualMachine.PowerOnVM_Task"


class TestScenario:
    @staticmethod
    def _both(extra: list[str]) -> list[str]:
        return generate(main, count=800, backfill="2h", extra=["--format", "both", *extra])

    def test_host_failure_raises_vmkernel_error_fraction(self) -> None:
        base = self._both([])
        scen = self._both(["--scenario", "host-failure"])
        base_frac = sum(STORAGE_ERR in line for line in base) / len(base)
        scen_frac = sum(STORAGE_ERR in line for line in scen) / len(scen)
        assert base_frac < 0.10
        assert scen_frac > base_frac * 2

    def test_host_failure_produces_ha_restart_events(self) -> None:
        scen = self._both(["--scenario", "host-failure"])
        assert any(HA_RESTART in line for line in scen)

    def test_baseline_has_no_ha_restart_events(self) -> None:
        assert not any(HA_RESTART in line for line in self._both([]))

    def test_storage_errors_concentrate_on_one_failing_host(self) -> None:
        scen = self._both(["--scenario", "host-failure"])
        hosts = Counter(
            m.group(2) for line in scen if STORAGE_ERR in line and (m := ESXI_RE.match(line))
        )
        assert hosts
        _top_host, top_count = hosts.most_common(1)[0]
        assert top_count / sum(hosts.values()) > 0.6  # ONE host cascades

    def test_ha_restarts_move_failing_host_vms_onto_other_hosts(self) -> None:
        scen = self._both(["--scenario", "host-failure"])
        errs = Counter(
            m.group(2) for line in scen if STORAGE_ERR in line and (m := ESXI_RE.match(line))
        )
        failing = errs.most_common(1)[0][0]  # short name, e.g. esx-host-03
        # Inventory names exactly as the ESXi plane renders them in the syslog header.
        esxi_host_ids = {
            f"{m.group(2)}.corp.example.com" for line in scen if (m := ESXI_RE.match(line))
        }
        restarts = [line for line in scen if HA_RESTART in line]
        assert restarts
        for line in restarts:
            m = VC_RE.match(line)
            assert m, line
            # vCenter HA names the destination host by FQDN, byte-equal to the ESXi
            # plane's inventory string - a host-name join across planes succeeds.
            dest = re.search(r"on host (esx-host-\d+\.corp\.example\.com)$", m.group(4))
            assert dest, line
            dest_host = dest.group(1)
            assert dest_host in esxi_host_ids, line  # cross-plane join
            assert dest_host != f"{failing}.corp.example.com"  # restarted on a DIFFERENT host

    def test_host_connection_alarm_names_same_fqdn_as_esxi_cascade(self) -> None:
        # The vCenter red 'Host connection' alarm must name the exact inventory string
        # (FQDN) of the host whose vmkernel storage cascade appears on the ESXi plane.
        scen = self._both(["--scenario", "host-failure"])
        cascade = Counter(
            f"{m.group(2)}.corp.example.com"
            for line in scen
            if STORAGE_ERR in line and (m := ESXI_RE.match(line))
        )
        assert cascade
        cascade_fqdn = cascade.most_common(1)[0][0]
        red = [
            m.group(4)
            for line in scen
            if (m := VC_RE.match(line)) and HOST_CONN_ALARM in m.group(4)
        ]
        assert red  # the scenario raises the red host-connection alarm
        for body in red:
            host = re.search(r" on (esx-host-\d+\.corp\.example\.com): green -> red$", body)
            assert host, body
            assert host.group(1) == cascade_fqdn, body  # byte-equal cross-plane join

    def test_scsi_sense_varies_and_failing_host_uses_connectivity_sense(self) -> None:
        scen = generate(
            main,
            count=300,
            backfill="2h",
            extra=["--format", "esxi", "--scenario", "host-failure"],
        )
        err_hosts = Counter(
            m.group(2) for line in scen if STORAGE_ERR in line and (m := ESXI_RE.match(line))
        )
        assert err_hosts
        failing = err_hosts.most_common(1)[0][0]

        senses: Counter[str] = Counter()
        failing_senses: list[str] = []
        for line in scen:
            m = ESXI_RE.match(line)
            if not m or STORAGE_ERR not in line:
                continue
            s = SENSE_RE.search(line)
            assert s, line  # every storage error carries a parseable sense
            senses[s.group(1)] += 1
            if m.group(2) == failing:
                failing_senses.append(s.group(1))

        assert len(senses) > 1  # no longer one byte-identical hardcoded tuple
        assert failing_senses  # the failing host cascades storage errors
        for sense in failing_senses:
            # Connectivity / NOT READY sense, never ILLEGAL REQUEST (0x5 0x24).
            assert sense in CONNECTIVITY_SENSE, sense
            assert "0x5 0x24" not in sense, sense
