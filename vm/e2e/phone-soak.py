#!/usr/bin/env python3
"""Overnight soak of an Android phone hosting `azula compute`, unplugged and screen-off.

Drives nothing on the phone. A detached job in the VM writes a heartbeat every
minute (`<epoch> <uptime-seconds>`), and this script samples the phone over
wireless adb and probes the host over the relay, so one run answers three
questions: did the VM keep running, did the host stay reachable, and what did it
cost (battery, temperature, thermal status).

    export AZULA_COMPUTE_TOKEN_FILE=/path/to/token      # 0600; a grant that outlives the soak
    vm/e2e/phone-soak.py start   --out soak/            # start the heartbeat job
    vm/e2e/phone-soak.py monitor --out soak/ --adb 192.168.1.176:40983 --hours 10
    vm/e2e/phone-soak.py report  --out soak/            # pulls the heartbeat log, prints Markdown

`monitor` is safe to stop (Ctrl-C) and restart: it appends to `samples.csv`.
Run it under `caffeinate -dims` so the Mac stays awake all night. Job timeouts
can't outlive the grant, so the token must be valid past the end of the soak.
Uses only the Python standard library.

A heartbeat's two clocks tell a paused VM from a slow one. `uptime` stops when
the host pauses the VM; the guest's wall clock catches up at the next timesync
(every 5 minutes, over the host's proxy). Wall time passing faster than uptime
is time the VM was paused.
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

HB_EVERY = 60            # seconds between heartbeats
HB_GAP = 90              # a heartbeat this late is a gap
SAMPLE_EVERY = 600       # seconds between samples
HB_FILE = "soak-heartbeat.log"

FIELDS = ["utc", "adb", "battery_pct", "battery_temp_c", "plugged", "wake", "doze_deep", "doze_light",
          "thermal_status", "vm_process", "doctor_ok", "doctor_ms", "note"]


def log(msg):
    print(f"{datetime.now(timezone.utc):%H:%M:%SZ} {msg}", flush=True)


def run(cmd, timeout, env=None):
    """(rc, stdout, seconds); rc None on timeout or a missing program."""
    began = time.monotonic()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env, text=True,
                           errors="replace")
        return p.returncode, p.stdout, time.monotonic() - began
    except subprocess.TimeoutExpired as e:
        return None, (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), \
            time.monotonic() - began
    except FileNotFoundError:
        return None, "not found: " + cmd[0], 0.0


class Azula:
    def __init__(self, binary, vm, token_file):
        self.bin, self.vm = binary, vm
        self.env = dict(os.environ)
        if token_file:
            with open(token_file) as f:
                self.env["AZULA_COMPUTE_TOKEN"] = f.read().strip()
        if not self.env.get("AZULA_COMPUTE_TOKEN"):
            sys.exit("set AZULA_COMPUTE_TOKEN_FILE (or AZULA_COMPUTE_TOKEN)")
        self.env.setdefault("AZULA_RELAY_ONLY", "1")

    def __call__(self, *args, timeout=120):
        return run([self.bin, "compute", *args], timeout, self.env)


class Adb:
    """Wireless adb that reconnects by itself: the address, or a device's mDNS name, can change."""

    def __init__(self, serial, adb="adb"):
        self.serial, self.adb = serial, adb

    def shell(self, script, timeout=30):
        rc, out, _ = run([self.adb, "-s", self.serial, "shell", script], timeout)
        if rc == 0:
            return out
        run([self.adb, "disconnect", self.serial], 10)
        run([self.adb, "connect", self.serial], 15)
        rc, out, _ = run([self.adb, "-s", self.serial, "shell", script], timeout)
        return out if rc == 0 else None


def phone_state(adb, pkg):
    """One sample as a dict, or None if adb isn't answering."""
    script = (
        "dumpsys battery | grep -E 'level|temperature|AC powered|USB powered|Wireless powered|status'; "
        "dumpsys power | grep -m1 mWakefulness=; "
        "echo DOZE_DEEP=$(dumpsys deviceidle get deep); echo DOZE_LIGHT=$(dumpsys deviceidle get light); "
        "dumpsys thermalservice | grep -m1 -i 'Thermal Status'; "
        f"echo VMPROC=$(ps -A -o NAME | grep -cE '^{pkg}:vmhost|crosvm_azula')"
    )
    out = adb.shell(script)
    if out is None:
        return None
    get = lambda pat: (re.search(pat, out) or [None, ""])[1] if re.search(pat, out) else ""
    temp = get(r"temperature:\s*(\d+)")
    plugged = [k for k in ("AC", "USB", "Wireless") if re.search(rf"{k} powered: true", out)]
    return {
        "battery_pct": get(r"level:\s*(\d+)"),
        "battery_temp_c": f"{int(temp) / 10:.1f}" if temp else "",
        "plugged": "+".join(plugged) or "no",
        "wake": get(r"mWakefulness=(\w+)"),
        "doze_deep": get(r"DOZE_DEEP=(\w+)"),
        "doze_light": get(r"DOZE_LIGHT=(\w+)"),
        "thermal_status": get(r"Thermal Status:\s*(\d+)"),
        "vm_process": get(r"VMPROC=(\d+)"),
    }


def cmd_start(a, az):
    os.makedirs(a.out, exist_ok=True)
    script = (f"echo '# soak heartbeats: epoch uptime' > $HOME/{HB_FILE}; "
              f"while :; do line=\"$(date -u +%s) $(cut -d' ' -f1 /proc/uptime)\"; "
              f"echo \"$line\" >> $HOME/{HB_FILE}; echo \"$line\"; sleep {a.every}; done")
    rc, out, _ = az("exec", "--detach", "--label", "phone-soak", "--timeout", a.job_timeout, "--vm", a.vm, "--",
                    "sh", "-c", script)
    ref = next((l.strip() for l in (out or "").splitlines() if re.match(r"^[\w.-]+/j_", l.strip())), "")
    if rc != 0 or not ref:
        sys.exit(f"couldn't start the heartbeat job (rc {rc}):\n{out}")
    with open(os.path.join(a.out, "job.json"), "w") as f:
        json.dump({"ref": ref, "started_utc": datetime.now(timezone.utc).isoformat(), "every": a.every}, f)
    log(f"heartbeat job {ref} started")
    return 0


def cmd_monitor(a, az):
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, "samples.csv")
    fresh = not os.path.exists(path)
    adb = Adb(a.adb)
    end = time.time() + a.hours * 3600
    n = 0
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, FIELDS)
        if fresh:
            w.writeheader()
        while time.time() < end:
            began = time.time()
            st = phone_state(adb, a.pkg)
            row = {k: "" for k in FIELDS}
            row["utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            row["adb"] = "ok" if st else "lost"
            if st:
                row.update(st)
            ok, ms = "", ""
            if not a.no_doctor:
                rc, out, secs = az("doctor", "--vm", a.vm, timeout=90)
                ok, ms = ("1" if rc == 0 else "0"), int(secs * 1000)
                if rc != 0:
                    bad = [l for l in (out or "").splitlines() if l.strip().startswith("✗")]
                    row["note"] = (bad[0].strip() if bad else f"rc={rc}")[:160]
            row["doctor_ok"], row["doctor_ms"] = ok, ms
            w.writerow(row)
            f.flush()
            n += 1
            log(f"sample {n}: adb={row['adb']} battery={row['battery_pct']}% {row['battery_temp_c']}C "
                f"thermal={row['thermal_status']} doze={row['doze_deep']}/{row['doze_light']} doctor={ok} {ms}ms "
                f"{row['note']}")
            left = min(a.every_sample - (time.time() - began), end - time.time())
            if left > 0:
                time.sleep(left)
    return 0


def analyze(lines, every=HB_EVERY, gap=HB_GAP):
    """Pure: heartbeat text -> a summary dict. `lines` are '<epoch> <uptime>'."""
    beats = []
    for l in lines:
        m = re.match(r"^(\d{9,})\s+([\d.]+)\s*$", l.strip())
        if m:
            beats.append((int(m[1]), float(m[2])))
    if len(beats) < 2:
        return {"beats": len(beats)}
    gaps = []
    for (e0, u0), (e1, u1) in zip(beats, beats[1:]):
        d = e1 - e0
        if d > gap:
            gaps.append({"at": e0, "late_s": d - every, "paused_s": max(0, round((e1 - e0) - (u1 - u0)))})
    wall = beats[-1][0] - beats[0][0]
    up = beats[-1][1] - beats[0][1]
    return {
        "beats": len(beats), "first": beats[0][0], "last": beats[-1][0], "wall_s": wall, "uptime_s": round(up, 1),
        "expected": wall // every + 1, "missing": max(0, wall // every + 1 - len(beats)),
        "gaps": gaps, "longest_gap_s": max([g["late_s"] + every for g in gaps], default=0),
        "paused_total_s": max(0, round(wall - up)),
    }


def cmd_report(a, az):
    job = json.load(open(os.path.join(a.out, "job.json")))
    hb = os.path.join(a.out, HB_FILE)
    rc, out, _ = az("pull", "--vm", a.vm, HB_FILE, hb, timeout=300)
    if rc != 0:
        log(f"couldn't pull the heartbeat log (rc {rc}): {out.strip()[:200]}")
    lines = open(hb).read().splitlines() if os.path.exists(hb) else []
    s = analyze(lines, job.get("every", HB_EVERY))
    fmt = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%m-%d %H:%MZ")
    print("# Phone soak\n")
    if s.get("beats", 0) < 2:
        print(f"Only {s.get('beats', 0)} heartbeats; nothing to report.")
        return 1
    print(f"- **Heartbeats:** {s['beats']} in {s['wall_s'] / 3600:.1f} h, {fmt(s['first'])} to {fmt(s['last'])}; "
          f"expected about {s['expected']}, {s['missing']} missing.")
    print(f"- **Gaps over {HB_GAP} s:** {len(s['gaps'])}. Longest: {s['longest_gap_s']} s.")
    for g in s["gaps"][:20]:
        print(f"  - {fmt(g['at'])}: {g['late_s']} s late, of which about {g['paused_s']} s the VM was paused")
    print(f"- **VM clock:** the guest's wall clock moved {s['wall_s']} s while its uptime moved {s['uptime_s']} s "
          f"({s['paused_total_s']} s paused in all).")
    p = os.path.join(a.out, "samples.csv")
    if os.path.exists(p):
        rows = list(csv.DictReader(open(p)))
        ok = [r for r in rows if r["adb"] == "ok"]
        pct = [int(r["battery_pct"]) for r in ok if r["battery_pct"]]
        temps = [float(r["battery_temp_c"]) for r in ok if r["battery_temp_c"]]
        docs = [r for r in rows if r["doctor_ok"] != ""]
        if pct:
            hours = max((datetime.fromisoformat(ok[-1]["utc"]) - datetime.fromisoformat(ok[0]["utc"])).total_seconds()
                        / 3600, 0.01)
            print(f"- **Battery:** {pct[0]}% -> {pct[-1]}% over {hours:.1f} h ({(pct[0] - pct[-1]) / hours:.1f}%/h).")
        if temps:
            print(f"- **Temperature:** battery {min(temps):.1f} to {max(temps):.1f} C. "
                  f"Thermal status max {max((int(r['thermal_status']) for r in ok if r['thermal_status']), default=0)} "
                  f"(0 = none, 1 = light, 2 = moderate).")
        print(f"- **Samples:** {len(rows)}, adb lost in {len(rows) - len(ok)}. Doze deep states seen: "
              f"{', '.join(sorted({r['doze_deep'] for r in ok if r['doze_deep']}))}. VM process present in "
              f"{sum(1 for r in ok if r['vm_process'] not in ('', '0'))}/{len(ok)}.")
        if docs:
            good = [r for r in docs if r["doctor_ok"] == "1"]
            ms = sorted(int(r["doctor_ms"]) for r in good if r["doctor_ms"])
            print(f"- **Relay reachability:** doctor passed {len(good)}/{len(docs)} times"
                  + (f"; median {ms[len(ms) // 2]} ms." if ms else "."))
            for r in [r for r in docs if r["doctor_ok"] != "1"][:10]:
                print(f"  - {r['utc']}: {r['note']}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["start", "monitor", "report"])
    ap.add_argument("--out", required=True, help="directory for the run's files")
    ap.add_argument("--azula", default="target/release/azula")
    ap.add_argument("--vm", default="default")
    ap.add_argument("--adb", help="adb serial of the phone (wireless ip:port) for monitor")
    ap.add_argument("--pkg", default="app.azula.dev", help="package whose :vmhost process hosts the VM")
    ap.add_argument("--hours", type=float, default=10)
    ap.add_argument("--every", type=int, default=HB_EVERY, help="seconds between heartbeats (start)")
    ap.add_argument("--every-sample", type=int, default=SAMPLE_EVERY, help="seconds between samples (monitor)")
    ap.add_argument("--job-timeout", default="24h")
    ap.add_argument("--no-doctor", action="store_true", help="monitor: skip the relay probe")
    ap.add_argument("--token-file", default=os.environ.get("AZULA_COMPUTE_TOKEN_FILE"))
    a = ap.parse_args()
    if a.cmd == "monitor" and not a.adb:
        ap.error("--adb is required for monitor")
    az = Azula(a.azula, a.vm, a.token_file)
    return {"start": cmd_start, "monitor": cmd_monitor, "report": cmd_report}[a.cmd](a, az)


if __name__ == "__main__":
    sys.exit(main())
