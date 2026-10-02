import os
import json
import urllib.error
import urllib.request
import fastapi
import uvicorn
import psutil
import asyncio
import time
import socket
import threading
import logging
from collections import deque
from typing import Deque, Dict, Any
from pathlib import Path
from datetime import datetime
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

# --- IMPROVEMENT: Basic logging configuration ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Configuration
SAMPLE_INTERVAL_SECONDS = 5
MAX_SAMPLES = (12 * 60 * 60) // SAMPLE_INTERVAL_SECONDS
PERSISTENCE_FILE = Path("monthly_traffic.json")
SAVE_INTERVAL_MINUTES = 5

# --- Automatic capacity measurement ---
# The agent actively measures the server's achievable download capacity and reports it in
# /api/v1/stats/bandwidth. Estimate = max(probe goodput, NIC RX rate during the probe):
# users consuming bandwidth while probing are part of the measurement (port is shared), so
# even a fully saturated port yields ~capacity. A throttling remote endpoint can only
# *underestimate* capacity -> conservative load numbers. Probes re-request small payloads
# in a loop: Cloudflare 403s bytes= params above ~25MB and the default urllib UA (verified);
# fixed-size test files are re-fetched until the budget is met.
CAPACITY_STATE_FILE = Path("capacity_state.json")
CAPACITY_REMEASURE_SECONDS = 60 * 60
PROBE_ENDPOINTS = [
    ("cloudflare", "https://speed.cloudflare.com/__down?bytes=25000000"),
    ("cachefly", "http://cachefly.cachefly.net/100mb.test"),
    ("ovh", "https://proof.ovh.net/files/100Mb.dat"),
]
PROBE_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
PROBE_MIN_SECONDS = 2.0        # min window before the byte budget may stop the probe
PROBE_MIN_BYTES = 25_000_000   # NIC RX delta (probe + user traffic) wanted for a stable ratio
PROBE_MAX_SECONDS = 10.0       # hard time ceiling (slow links stop here, ~12.5 MB @ 10 Mbps)
PROBE_MAX_BYTES = 400_000_000  # hard byte ceiling (multi-gigabit ports stop here)
PROBE_WARMUP_SECONDS = 1.0     # excluded from the ratios (TCP slow start)
PROBE_CHUNK_BYTES = 1 << 18
PROBE_NIC_POLL_SECONDS = 0.1   # NIC counter read throttle inside the download loop
PROBE_MIN_USABLE_MBPS = 5.0    # below this the estimate is rejected and the next endpoint is tried
PROBE_MIN_USABLE_BYTES = 1_000_000
PROBE_CONNECT_TIMEOUT = 10

# API Key Setup
API_KEY = os.getenv("BANDWIDTH_API_KEY", "insecure-default-key-change-me")
if API_KEY == "insecure-default-key-change-me":
    logging.warning(
        "You are using a default, insecure API key. Please set BANDWIDTH_API_KEY."
    )

api_key_header_scheme = APIKeyHeader(name="X-API-Key")


async def get_api_key(api_key: str = Depends(api_key_header_scheme)):
    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or Missing API Key",
        )


# Helper Functions
def get_default_interface_name() -> str:
    logging.info(
        "Attempting to automatically determine the default network interface..."
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip_address = s.getsockname()[0]
        for interface_name, snic_addrs in psutil.net_if_addrs().items():
            for snic_addr in snic_addrs:
                if (
                    snic_addr.family == socket.AF_INET
                    and snic_addr.address == local_ip_address
                ):
                    logging.info(
                        f"✅ Successfully determined default network interface: '{interface_name}'"
                    )
                    return interface_name
    except Exception as e:
        logging.warning(
            f"Could not determine default interface, falling back to 'eth0'. Error: {e}"
        )
        return "eth0"


def format_bytes(byte_count: int) -> str:
    if byte_count is None:
        return "0 B"
    power = 1024
    n = 0
    power_labels = {0: "", 1: "K", 2: "M", 3: "G", 4: "T"}
    while byte_count >= power and n < len(power_labels) - 1:
        byte_count /= power
        n += 1
    return f"{byte_count:.2f} {power_labels[n]}B"


# Global State
NETWORK_INTERFACE = get_default_interface_name()
sent_samples: Deque[float] = deque()
recv_samples: Deque[float] = deque()
running_total_sent: float = 0.0
running_total_recv: float = 0.0
monthly_traffic_state: Dict[str, Any] = {}
capacity_state: Dict[str, Any] = {
    "capacity_mbps": None,
    "measured_at": None,
    "endpoint": None,
    "probe_bytes_month": 0,
    "month": None,
}
GLOBAL_LOCK = threading.Lock()
app = fastapi.FastAPI()


# Persistence Functions
def load_monthly_traffic():
    global monthly_traffic_state
    current_month = datetime.now().strftime("%Y-%m")
    if PERSISTENCE_FILE.exists():
        try:
            with open(PERSISTENCE_FILE, "r") as f:
                data = json.load(f)
            if data.get("month") == current_month:
                monthly_traffic_state = data
                logging.info(f"✅ Loaded traffic data for month {current_month}.")
                return
        except (json.JSONDecodeError, IOError) as e:
            logging.error(
                f"Could not read persistence file. Starting fresh. Error: {e}"
            )

    logging.info(f"✨ Initializing new traffic log for month {current_month}.")
    monthly_traffic_state = {
        "month": current_month,
        "total_bytes_sent": 0,
        "total_bytes_recv": 0,
    }


async def save_monthly_traffic_periodically():
    while True:
        await asyncio.sleep(SAVE_INTERVAL_MINUTES * 60)
        with GLOBAL_LOCK:
            state_to_save = monthly_traffic_state.copy()
        try:
            with open(PERSISTENCE_FILE, "w") as f:
                json.dump(state_to_save, f, indent=4)
            logging.info("💾 Persisted monthly traffic data.")
        except IOError as e:
            logging.error(f"❌ Error saving persistence file: {e}")


# Background Tasks
def load_capacity_state():
    global capacity_state
    if CAPACITY_STATE_FILE.exists():
        try:
            with open(CAPACITY_STATE_FILE, "r") as f:
                data = json.load(f)
            if isinstance(data, dict) and (
                data.get("capacity_mbps") is None or isinstance(data.get("capacity_mbps"), (int, float))
            ):
                data.setdefault("probe_bytes_month", 0)
                data.setdefault("month", datetime.now().strftime("%Y-%m"))
                capacity_state = data
                logging.info(
                    f"✅ Loaded last measured capacity: {capacity_state.get('capacity_mbps')} Mbps"
                    f" (measured at {capacity_state.get('measured_at')})."
                )
                return
        except (json.JSONDecodeError, IOError) as e:
            logging.error(f"Could not read capacity state file, starting fresh. Error: {e}")
    capacity_state = {
        "capacity_mbps": None,
        "measured_at": None,
        "endpoint": None,
        "probe_bytes_month": 0,
        "month": datetime.now().strftime("%Y-%m"),
    }


def _read_rx_bytes() -> int:
    net_io = psutil.net_io_counters(pernic=True).get(NETWORK_INTERFACE, psutil.net_io_counters())
    return net_io.bytes_recv


def _probe_endpoint(url: str) -> Dict[str, Any]:
    """Actively download from `url` until the time/byte budget is met.

    Blocking (run via asyncio.to_thread). Re-requests the URL in a loop so any endpoint,
    regardless of payload size, fills the budget. Returns per-endpoint estimates; the NIC
    RX rate over the probe window is the primary estimate (includes concurrent user
    traffic), goodput is a floor. The first PROBE_WARMUP_SECONDS are excluded from the
    ratios; if the budget stops before warm-up completes (very fast ports), full-window
    ratios are used instead.
    """
    t0 = time.monotonic()
    rx_start = _read_rx_bytes()
    warm_marked = False
    warm_time = t0
    warm_rx = rx_start
    warm_probe_bytes = 0
    probe_bytes = 0
    last_nic_poll = t0
    stopped = False

    while not stopped:
        request = urllib.request.Request(url, headers={"User-Agent": PROBE_USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=PROBE_CONNECT_TIMEOUT) as response:
                while True:
                    chunk = response.read(PROBE_CHUNK_BYTES)
                    if not chunk:
                        break
                    probe_bytes += len(chunk)
                    now = time.monotonic()
                    if not warm_marked and now - t0 >= PROBE_WARMUP_SECONDS:
                        warm_marked = True
                        warm_time = now
                        warm_rx = _read_rx_bytes()
                        warm_probe_bytes = probe_bytes
                    if now - last_nic_poll >= PROBE_NIC_POLL_SECONDS:
                        last_nic_poll = now
                        elapsed = now - t0
                        nic_delta = max(_read_rx_bytes() - rx_start, 0)
                        if (
                            elapsed >= PROBE_MAX_SECONDS
                            or nic_delta >= PROBE_MAX_BYTES
                            or (elapsed >= PROBE_MIN_SECONDS and nic_delta >= PROBE_MIN_BYTES)
                        ):
                            stopped = True
                            break
        except Exception:
            # One failed fetch must not fail the whole probe (req: resilience): a transfer
            # that died mid-window with usable data is salvaged; with nothing usable the
            # endpoint raises and the caller moves on to the next one.
            if probe_bytes >= PROBE_MIN_USABLE_BYTES:
                logging.warning(f"Probe transfer failed mid-window; salvaging {format_bytes(probe_bytes)}.")
                break
            raise

    t_end = time.monotonic()
    rx_end = _read_rx_bytes()
    nic_delta = max(rx_end - rx_start, 0)
    if warm_marked and t_end - warm_time > 0.5:
        window = t_end - warm_time
        goodput_mbps = (probe_bytes - warm_probe_bytes) * 8 / window / 1_000_000
        nic_rx_mbps = max(rx_end - warm_rx, 0) * 8 / window / 1_000_000
    else:
        window = max(t_end - t0, 0.001)
        goodput_mbps = probe_bytes * 8 / window / 1_000_000
        nic_rx_mbps = nic_delta * 8 / window / 1_000_000
    return {
        "goodput_mbps": goodput_mbps,
        "nic_rx_mbps": nic_rx_mbps,
        "nic_delta_bytes": nic_delta,
        "probe_bytes": probe_bytes,
        "elapsed_seconds": t_end - t0,
    }


async def measure_capacity_once():
    """Try each probe endpoint in order; stop at the first usable estimate.

    Usable = max(goodput, NIC RX rate) >= PROBE_MIN_USABLE_MBPS and the NIC actually moved
    >= PROBE_MIN_USABLE_BYTES (gates on NIC delta, not probe bytes: when users already
    saturate the port the probe pulls ~0 yet the NIC delta still measures ~capacity).
    """
    for name, url in PROBE_ENDPOINTS:
        logging.info(f"📏 Measuring achievable capacity via {name}...")
        try:
            result = await asyncio.to_thread(_probe_endpoint, url)
        except Exception as e:
            logging.warning(f"Capacity probe via {name} failed: {type(e).__name__}: {e}")
            continue
        estimate_mbps = max(result["goodput_mbps"], result["nic_rx_mbps"])
        if estimate_mbps < PROBE_MIN_USABLE_MBPS or result["nic_delta_bytes"] < PROBE_MIN_USABLE_BYTES:
            logging.warning(
                f"Capacity probe via {name} unusable (estimate {estimate_mbps:.1f} Mbps,"
                f" NIC delta {format_bytes(result['nic_delta_bytes'])}); trying next endpoint."
            )
            continue
        with GLOBAL_LOCK:
            current_month = datetime.now().strftime("%Y-%m")
            if capacity_state.get("month") != current_month:
                capacity_state["month"] = current_month
                capacity_state["probe_bytes_month"] = 0
            capacity_state["capacity_mbps"] = round(estimate_mbps, 2)
            capacity_state["measured_at"] = datetime.now().isoformat()
            capacity_state["endpoint"] = name
            capacity_state["probe_bytes_month"] = capacity_state.get("probe_bytes_month", 0) + result["probe_bytes"]
            snapshot = dict(capacity_state)
        try:
            with open(CAPACITY_STATE_FILE, "w") as f:
                json.dump(snapshot, f, indent=4)
        except IOError as e:
            logging.error(f"❌ Error saving capacity state: {e}")
        logging.info(
            f"✅ Capacity measured: {snapshot['capacity_mbps']} Mbps via {name}"
            f" (probe downloaded {format_bytes(result['probe_bytes'])} in {result['elapsed_seconds']:.1f}s)."
        )
        return
    logging.error("❌ All capacity probes failed — keeping last known value.")


async def capacity_measurement_loop():
    # ponytail: fresh hourly value beats EMA smoothing; a bad hour self-corrects the next hour
    while True:
        try:
            await measure_capacity_once()
        except Exception as e:
            logging.error(f"Capacity measurement loop error: {e}")
        await asyncio.sleep(CAPACITY_REMEASURE_SECONDS)


async def monitor_bandwidth():
    global running_total_sent, running_total_recv, monthly_traffic_state
    try:
        net_io_initial = psutil.net_io_counters(pernic=True).get(
            NETWORK_INTERFACE, psutil.net_io_counters()
        )
        last_bytes_sent = net_io_initial.bytes_sent
        last_bytes_recv = net_io_initial.bytes_recv
    except Exception as e:
        logging.error(
            f"❌ FATAL: Could not get initial network stats. Monitoring task will not run. Error: {e}"
        )
        return

    last_check_time = time.time()
    while True:
        await asyncio.sleep(SAMPLE_INTERVAL_SECONDS)
        current_time = time.time()
        time_delta = current_time - last_check_time
        try:
            net_io = psutil.net_io_counters(pernic=True).get(
                NETWORK_INTERFACE, psutil.net_io_counters()
            )
            bytes_sent_delta = net_io.bytes_sent - last_bytes_sent
            bytes_recv_delta = net_io.bytes_recv - last_bytes_recv
            if time_delta > 0:
                speed_sent_mbps = (bytes_sent_delta * 8) / 1_000_000 / time_delta
                speed_recv_mbps = (bytes_recv_delta * 8) / 1_000_000 / time_delta
                with GLOBAL_LOCK:
                    sent_samples.append(speed_sent_mbps)
                    running_total_sent += speed_sent_mbps
                    if len(sent_samples) > MAX_SAMPLES:
                        running_total_sent -= sent_samples.popleft()

                    recv_samples.append(speed_recv_mbps)
                    running_total_recv += speed_recv_mbps
                    if len(recv_samples) > MAX_SAMPLES:
                        running_total_recv -= recv_samples.popleft()

                    current_month = datetime.now().strftime("%Y-%m")
                    if monthly_traffic_state.get("month") != current_month:
                        logging.info(
                            f"🎉 Month rolled over to {current_month}. Resetting monthly traffic."
                        )
                        monthly_traffic_state = {
                            "month": current_month,
                            "total_bytes_sent": 0,
                            "total_bytes_recv": 0,
                        }
                    monthly_traffic_state["total_bytes_sent"] += bytes_sent_delta
                    monthly_traffic_state["total_bytes_recv"] += bytes_recv_delta

            last_bytes_sent = net_io.bytes_sent
            last_bytes_recv = net_io.bytes_recv
            last_check_time = current_time
        except Exception as e:
            logging.error(f"Error during network stats collection: {e}")


# API Endpoints
@app.get("/api/v1/stats/bandwidth", dependencies=[Depends(get_api_key)])
def get_bandwidth_stats():
    with GLOBAL_LOCK:
        if not sent_samples:
            avg_sent, avg_recv, current_count = 0.0, 0.0, 0
        else:
            current_count = len(sent_samples)
            avg_sent = running_total_sent / current_count
            avg_recv = running_total_recv / current_count
        capacity_mbps = capacity_state.get("capacity_mbps")
        capacity_measured_at = capacity_state.get("measured_at")
    return {
        "network_interface": NETWORK_INTERFACE,
        "average_speed_mbps": {
            "sent": round(avg_sent, 2),
            "received": round(avg_recv, 2),
            "total": round(avg_sent + avg_recv, 2),
        },
        "capacity_mbps": capacity_mbps,
        "capacity_measured_at": capacity_measured_at,
        "period_seconds": MAX_SAMPLES * SAMPLE_INTERVAL_SECONDS,
        "current_sample_count": current_count,
        "max_samples_for_avg": MAX_SAMPLES,
    }


@app.get("/api/v1/stats/monthly-traffic", dependencies=[Depends(get_api_key)])
def get_monthly_traffic():
    with GLOBAL_LOCK:
        state = monthly_traffic_state.copy()
        capacity_snapshot = dict(capacity_state)
    # Capacity probes are our own measurement overhead flowing through the same NIC —
    # report monthly traffic net of probe bytes so users aren't billed for them.
    probe_bytes = (
        capacity_snapshot.get("probe_bytes_month", 0) if state.get("month") == capacity_snapshot.get("month") else 0
    )
    total_bytes_recv = max(state.get("total_bytes_recv", 0) - probe_bytes, 0)
    total_bytes = state.get("total_bytes_sent", 0) + total_bytes_recv
    return {
        "month": state.get("month"),
        "data_usage": {
            "sent": format_bytes(state.get("total_bytes_sent", 0)),
            "received": format_bytes(total_bytes_recv),
            "total": format_bytes(total_bytes),
        },
        "raw_bytes": {
            "sent": state.get("total_bytes_sent", 0),
            "received": total_bytes_recv,
            "total": total_bytes,
        },
    }


# FastAPI Lifecycle
@app.on_event("startup")
async def startup_event():
    logging.info("🚀 Server starting up...")
    load_monthly_traffic()
    load_capacity_state()
    asyncio.create_task(monitor_bandwidth())
    asyncio.create_task(save_monthly_traffic_periodically())
    asyncio.create_task(capacity_measurement_loop())


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
