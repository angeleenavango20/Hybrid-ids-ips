"""
benchmark_pipeline.py — Measures REAL CPU usage, per-alert latency, and
throughput of the response pipeline (parser -> decision -> blocker),
using your actual project code. No numbers are invented; everything
printed here comes from an actual timed run.

WHAT THIS MEASURES (and what it deliberately does NOT):
- Measures: the response SCRIPT's own processing overhead per alert
  (parse -> decide -> would-block), and this process's CPU usage while
  doing that work.
- Does NOT measure: Suricata's own packet-to-alert detection latency,
  since that's a separate tool's internal performance, not your
  contribution. Keep that distinction clear if asked in the interview.

HOW TO RUN
    1. Copy this file into the same folder as parser.py, decision.py,
       blocker.py, ml_model.py (e.g. ~/response-script/).
    2. pip install psutil --break-system-packages   (if not already installed)
    3. python3 benchmark_pipeline.py
    4. Read the printed summary at the end.

SAFETY
    blocker.block_ip() is always called with dry_run=True here, so this
    NEVER touches a real firewall or opens a real SSH connection.
"""

import json
import os
import sys
import time
import threading
import statistics

try:
    import psutil
except ImportError:
    print("This script needs psutil. Install it with:")
    print("    pip install psutil --break-system-packages")
    sys.exit(1)

# Import your REAL pipeline code — this is what makes the benchmark honest.
try:
    from parser import parse_alert
    from decision import should_block
    from blocker import block_ip
except ImportError as e:
    print(f"Could not import your pipeline modules: {e}")
    print("Make sure this script sits in the same folder as parser.py, "
          "decision.py, and blocker.py.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Config — tweak these for a bigger/smaller test
# ---------------------------------------------------------------------------
N_ALERTS = 300          # how many synthetic alerts to feed through the pipeline
N_UNIQUE_IPS = 40       # spread across this many distinct source IPs
BURST_MODE = True       # True = fire alerts as fast as possible (max throughput);
                         # False = pace them out realistically (see PACE_SECONDS)
PACE_SECONDS = 0.05     # only used if BURST_MODE is False


def make_synthetic_alert(i):
    """Builds one alert in the shape parser.parse_alert() expects,
    matching real Suricata eve.json alert fields."""
    ip_index = i % N_UNIQUE_IPS
    severities = [1, 2, 3]
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime()),
        "event_type": "alert",
        "src_ip": f"10.50.{ip_index // 254}.{ip_index % 254 + 1}",
        "dest_port": 22 + (i % 10),
        "alert": {
            "severity": severities[i % 3],
            "signature": "BENCHMARK Synthetic Test Alert",
            "category": "Benchmark",
        },
    }
    return event


def run_pipeline_once(event):
    """Runs exactly the same sequence main.py's process_line() runs:
    parse -> decide -> (dry-run) block. Returns elapsed seconds."""
    start = time.perf_counter()
    alert = parse_alert(event)
    block, reason = should_block(alert)
    if block:
        block_ip(alert["source_ip"], dry_run=True)  # never touches real firewall
    return time.perf_counter() - start


def cpu_sampler(proc, samples, stop_flag):
    """Background thread: samples this process's own CPU% repeatedly."""
    proc.cpu_percent(interval=None)  # first call primes the internal counter
    while not stop_flag["stop"]:
        samples.append(proc.cpu_percent(interval=0.2))


def main():
    print(f"Running benchmark: {N_ALERTS} alerts across {N_UNIQUE_IPS} unique IPs")
    print(f"Mode: {'burst (max throughput)' if BURST_MODE else f'paced ({PACE_SECONDS}s between alerts)'}\n")

    proc = psutil.Process(os.getpid())
    cpu_samples = []
    stop_flag = {"stop": False}
    sampler_thread = threading.Thread(target=cpu_sampler, args=(proc, cpu_samples, stop_flag))
    sampler_thread.start()

    latencies = []
    mem_before = proc.memory_info().rss / (1024 * 1024)  # MB

    wall_start = time.perf_counter()
    for i in range(N_ALERTS):
        event = make_synthetic_alert(i)
        elapsed = run_pipeline_once(event)
        latencies.append(elapsed)
        if not BURST_MODE:
            time.sleep(PACE_SECONDS)
    wall_end = time.perf_counter()

    stop_flag["stop"] = True
    sampler_thread.join()
    mem_after = proc.memory_info().rss / (1024 * 1024)  # MB

    total_wall = wall_end - wall_start
    throughput = N_ALERTS / total_wall if total_wall > 0 else float("inf")

    latencies_ms = [l * 1000 for l in latencies]
    avg_latency = statistics.mean(latencies_ms)
    p95_latency = sorted(latencies_ms)[int(len(latencies_ms) * 0.95) - 1]
    max_latency = max(latencies_ms)
    min_latency = min(latencies_ms)

    avg_cpu = statistics.mean(cpu_samples) if cpu_samples else 0.0
    peak_cpu = max(cpu_samples) if cpu_samples else 0.0

    print("=" * 60)
    print("RESULTS (from this actual run — not estimated)")
    print("=" * 60)
    print(f"Total alerts processed:     {N_ALERTS}")
    print(f"Total wall-clock time:      {total_wall:.3f} s")
    print(f"Throughput:                 {throughput:.1f} alerts/sec")
    print()
    print(f"Per-alert latency (parse -> decide -> dry-run block):")
    print(f"  min:                      {min_latency:.3f} ms")
    print(f"  avg:                      {avg_latency:.3f} ms")
    print(f"  p95:                      {p95_latency:.3f} ms")
    print(f"  max:                      {max_latency:.3f} ms")
    print()
    print(f"CPU usage of this process during the run:")
    print(f"  avg:                      {avg_cpu:.1f}%")
    print(f"  peak:                     {peak_cpu:.1f}%")
    print()
    print(f"Memory (RSS) before run:    {mem_before:.1f} MB")
    print(f"Memory (RSS) after run:     {mem_after:.1f} MB")
    print("=" * 60)
    print("\nNote: this measures the response script's own overhead only.")
    print("Suricata's packet-to-alert detection latency is separate and")
    print("was not measured here.")


if __name__ == "__main__":
    main()
