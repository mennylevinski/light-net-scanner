#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Author: Menny Levinski

Advanced Network Scanner:
LAN discovery & port audit tool.

Windows:
python advanced_net_scanner.py

Linux:
chmod +x advanced_net_scanner.py
python3 advanced_net_scanner.py
"""

import io
import os
import re
import sys
import time
import uuid
import platform
import socket
import logging
import datetime
import ipaddress
import subprocess
import concurrent.futures
import threading
import itertools
from typing import List, Dict, Iterable, Optional
from io import StringIO
from typing import Optional

log_buffer = io.StringIO()
now = datetime.datetime.now().replace(microsecond=0)

# ====== Logger Setup =======
def setup_logger(level=logging.INFO, logfile: Optional[str] = None):
    """Configure root logger. Call once at program start."""
    
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(message)s"))  

    handlers = [ch]

    fh = None
    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        handlers.append(fh)

    sh = logging.StreamHandler(log_buffer)
    sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    handlers.append(sh)

    logging.basicConfig(level=level, handlers=handlers)

# ======= Console helper =======
def ensure_console(title: str = "Advanced Network Scanner"):
    """Ensure a console is available on Windows with black background / white text."""
    if sys.platform.startswith("win"):
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32

            ATTACH_PARENT_PROCESS = -1
            if not kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
                kernel32.AllocConsole()

            sys.stdout = open("CONOUT$", "w", buffering=1, encoding="utf-8", errors="ignore")
            sys.stderr = open("CONOUT$", "w", buffering=1, encoding="utf-8", errors="ignore")
            sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="ignore")

            try:
                kernel32.SetConsoleTitleW(str(title))
            except Exception:
                pass

            try:
                os.system("color 07")
            except Exception:
                pass
        except Exception:
            pass

def _limit_str(s: Optional[str], max_len: int = 23) -> Optional[str]:
    if not s:
        return s
    return s if len(s) <= max_len else s[:max_len - 3] + "..."

# ======= Spinner (moving dots) =======
class Spinner:
    """Simple console spinner/dots animation in a separate thread."""
    def __init__(self, message: str = "Running scan"):
        self.message = message
        self._stop_event = threading.Event()
        self.thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for dots in itertools.cycle(["", ".", "..", "...", "....", "....."]):
            if self._stop_event.is_set():
                break
            print(f"\r{self.message}{dots}   ", end="", flush=True)
            time.sleep(0.5)
            
        print("\r" + " " * (len(self.message) + 10) + "\r", end="", flush=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        self.thread.join()

# Default common ports to check quickly
COMMON_PORTS = [21, 22, 23, 67, 68, 69, 80, 53, 123, 137, 138, 161, 389, 443, 445, 1433, 3389, 5900]

# OS detection
IS_WINDOWS = platform.system().lower().startswith("win")

# Windows-specific flags to hide console windows for subprocess children
if IS_WINDOWS:
    WINDOWS_CREATE_NO_WINDOW = 0x08000000
    try:
        STARTUPINFO = subprocess.STARTUPINFO()
        STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        STARTUPINFO.wShowWindow = subprocess.SW_HIDE
    except Exception:
        STARTUPINFO = None
else:
    WINDOWS_CREATE_NO_WINDOW = 0
    STARTUPINFO = None

def _subproc_kwargs_hide_window() -> dict:
    if IS_WINDOWS:
        kwargs = {"creationflags": WINDOWS_CREATE_NO_WINDOW}
        if STARTUPINFO is not None:
            kwargs["startupinfo"] = STARTUPINFO
        return kwargs
    return {}

def _run_check_output(cmd, shell=False, **kwargs) -> str:
    base_kwargs = {"text": True, "encoding": "utf-8", "errors": "ignore", "shell": shell}
    base_kwargs.update(_subproc_kwargs_hide_window())
    base_kwargs.update(kwargs)
    return subprocess.check_output(cmd, **base_kwargs)

def _run_subprocess_run(cmd, shell=False, **kwargs) -> subprocess.CompletedProcess:
    base_kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "shell": shell}
    base_kwargs.update(_subproc_kwargs_hide_window())
    base_kwargs.update(kwargs)
    return subprocess.run(cmd, **base_kwargs)

def _local_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def guess_subnet(ip: Optional[str], mask_bits: int = 24) -> ipaddress.IPv4Network:
    if not ip:
        return ipaddress.ip_network("0.0.0.0/0")
    return ipaddress.ip_network(f"{ip}/{mask_bits}", strict=False)

def _ping(ip: str, timeout_ms: int = 100, rate: int = 50) -> bool:

    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
            proc = _run_subprocess_run(cmd, shell=False)
        else:
            timeout_s = max(1, int((timeout_ms + 999) // 1000))
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
            proc = _run_subprocess_run(cmd, shell=False)

        # throttle ping frequency
        if rate > 0:
            time.sleep(1 / rate)

        return proc.returncode == 0
    except Exception:
        return False

def _parse_arp_table() -> Dict[str, str]:
    ip_to_mac = {}
    try:
        out = _run_check_output(["arp", "-a"], shell=False)
        if IS_WINDOWS:
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{14,17})", line)
                if m:
                    ip, mac = m.group(1), m.group(2).replace("–", ":").lower()
                    ip_to_mac[ip] = mac
        else:
            for line in out.splitlines():
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
                if m:
                    ip, mac = m.group(1), m.group(2).lower()
                    ip_to_mac[ip] = mac
    except Exception:
        pass
    return ip_to_mac

def _resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    # 1) Reverse DNS (cross-platform, safest)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            return fut.result(timeout=timeout)[0]
    except Exception:
        pass

    # Linux-only methods here
    if platform.system().lower() == "windows":
        return "N/A"

    # Helper: check if a command exists
    def cmd_exists(cmd: str) -> bool:
        return subprocess.call(
            f"command -v {cmd} >/dev/null 2>&1", shell=True
        ) == 0

    # 2) NetBIOS (nmblookup)
    if cmd_exists("nmblookup"):
        try:
            result = subprocess.check_output(
                ["nmblookup", "-A", ip],
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                text=True
            )
            for line in result.splitlines():
                if "<00>" in line and "GROUP" not in line:
                    return line.split()[0]
        except Exception:
            pass

    # 3) mDNS (avahi-resolve)
    if cmd_exists("avahi-resolve-address"):
        try:
            result = subprocess.check_output(
                ["avahi-resolve-address", ip],
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                text=True
            ).strip()

            if result and " " in result:
                return result.split()[-1]
        except Exception:
            pass

    return "N/A"

def _scan_ports(ip: str, ports: Iterable[int], timeout: float = 0.12, max_workers: int = 200) -> List[int]:
    open_ports = []
    ports_list = list(ports)
    if not ports_list:
        return []

    def _try_port(port: int) -> Optional[int]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except:
            pass
        return None

    worker_count = min(max_workers, len(ports_list))

    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as ex:
        futures = {ex.submit(_try_port, p): p for p in ports_list}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res is not None:
                open_ports.append(res)

    return sorted(open_ports)

def discover_hosts(subnet: ipaddress.IPv4Network, max_workers: int = 400, tcp_ports=None, timeout: float = 0.1) -> List[str]:
    if tcp_ports is None:
        tcp_ports = [22, 53, 139, 161, 443, 445]  # common ports for alive detection

    ips = [str(ip) for ip in subnet.hosts()]
    if not ips:
        return []

    def _fast_alive(ip):
        for port in tcp_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        return ip
            except:
                continue
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as ex:
        results = list(ex.map(_fast_alive, ips))

    alive = [ip for ip in results if ip]
    return sorted(alive, key=lambda x: socket.inet_aton(x))

def discover_network(subnet: Optional[ipaddress.IPv4Network] = None,
                     ports: Optional[Iterable[int]] = None,
                     do_port_scan: bool = True,
                     fast: bool = True) -> List[Dict]:

    if ports is None:
        ports = COMMON_PORTS

    local_ip = _local_ip()  # Detect local IP
    if subnet is None:
        subnet = guess_subnet(local_ip, 24)

    port_timeout = 0.4 if fast else 1.2
    tcp_timeout = 0.10 if fast else 0.3  # for fast host detection

    # Discover alive hosts using TCP connect (much faster than ping)
    alive_ips = discover_hosts(subnet, max_workers=400, timeout=tcp_timeout)

    # --- Skip local IP ---
    if local_ip in alive_ips:
        alive_ips.remove(local_ip)

    # Get ARP table for MAC addresses
    ip_mac = _parse_arp_table()

    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        port_futures = {}
        for ip in alive_ips:
            if do_port_scan:
                port_futures[ip] = ex.submit(_scan_ports, ip, ports, port_timeout, 200)

        for ip in alive_ips:
            hostname = "N/A" if fast else _resolve_hostname(ip, timeout=1.0)
            mac = ip_mac.get(ip)
            open_ports = []
            if do_port_scan and ip in port_futures:
                try:
                    open_ports = port_futures[ip].result(timeout=10)
                except Exception:
                    open_ports = []

            devices.append({
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "alive": True,
                "open_ports": open_ports
            })

    return devices

def _highlight_risky_ports(ports: Iterable[int]) -> List[str]:
    mapping = {}
    return [f"{p}({mapping.get(p,'')})" if p in mapping else str(p) for p in ports]

def _first_interface() -> Optional[str]:
    """Return the first non-loopback interface name on Linux or Windows."""
    system = platform.system().lower()
    try:
        if system == "linux":
            out = subprocess.check_output(["ip", "link"], text=True)
            m = re.findall(r"^\d+: (\S+):", out, re.MULTILINE)
            for iface in m:
                if iface != "lo":
                    return _limit_str(iface)
        elif system == "windows":
            cmd = [
                "powershell",
                "-Command",
                "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} "
                "| Select-Object -First 1 -ExpandProperty Name"
            ]
            out = subprocess.check_output(cmd, text=True).strip()
            if out:
                return _limit_str(out)
    except Exception:
        return None
    return None

def _primary_mac() -> Optional[str]:
    """Return primary system MAC address (best-effort, cross-platform)."""
    try:
        mac = uuid.getnode()
        return ":".join(f"{(mac >> i) & 0xff:02x}" for i in range(40, -1, -8))
    except Exception:
        return None

# ======= Print Setup =======
def test_print(
    subnet: Optional[ipaddress.IPv4Network] = None,
    do_port_scan: bool = True,
    fast: bool = True,
    ports: Optional[Iterable[int]] = None,
    silent: bool = False,
) -> list:
    if subnet is None:
        local = _local_ip()
        subnet = guess_subnet(local, 24)

    devices = discover_network(subnet=subnet, do_port_scan=do_port_scan, fast=fast, ports=ports)

    if silent:
        return devices

    # --- Print table ---
    headers = ["IP Address", "Hostname", "MAC", "Alive", "Open Ports"]
    col_widths = [15, 20, 20, 10, 40]

    def _trim(s: str, w: int) -> str:
        return (s[: w - 3] + "...") if len(s) > w else s

    header_line = "  ".join(h.center(w) for h, w in zip(headers, col_widths))
    sep_line = "–" * len(header_line)

    logging.info(f"\n\nScanned subnet: {subnet} — found {len(devices)} devices")
    logging.info(sep_line)
    logging.info(header_line)
    logging.info(sep_line)

    seen_ips = set()
    for d in devices:
        ip = d["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        host = _trim(d.get("hostname") or "N/A", col_widths[1])
        mac = _trim(d.get("mac") or "N/A", col_widths[2])
        alive = str(d["alive"])
        if d.get("open_ports"):
            ports_str = ", ".join(_highlight_risky_ports(d["open_ports"]))
        else:
            ports_str = "N/A"
        ports_str = _trim(ports_str, col_widths[4])

        logging.info(
            f"{ip.ljust(col_widths[0])}  {host.center(col_widths[1])}  "
            f"{mac.center(col_widths[2])}  {alive.center(col_widths[3])}  {ports_str.center(col_widths[4])}"
        )

    logging.info(sep_line)
    return devices

def print_devices(devices: list):
    # Same logic as test_print, just the printing part
    headers = ["IP Address", "Hostname", "MAC", "Alive", "Open Ports"]
    col_widths = [15, 20, 20, 10, 40]

    def _trim(s: str, w: int) -> str:
        return (s[: w - 3] + "...") if len(s) > w else s

    header_line = "  ".join(h.center(w) for h, w in zip(headers, col_widths))
    sep_line = "–" * len(header_line)

    logging.info(sep_line)
    logging.info(header_line)
    logging.info(sep_line)

    seen_ips = set()
    for d in devices:
        ip = d["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        host = _trim(d.get("hostname") or "N/A", col_widths[1])
        mac = _trim(d.get("mac") or "N/A", col_widths[2])
        alive = str(d["alive"])
        ports_str = _trim(
            ", ".join(_highlight_risky_ports(d.get("open_ports", []))) if d.get("open_ports") else "N/A",
            col_widths[4]
        )

        logging.info(
            f"{ip.ljust(col_widths[0])}  {host.center(col_widths[1])}  "
            f"{mac.center(col_widths[2])}  {alive.center(col_widths[3])}  {ports_str.center(col_widths[4])}"
        )

    logging.info(sep_line)

# --- Define private IP check ---
def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ======= Main =======
if __name__ == "__main__":
    ensure_console("Advanced Network Scanner")

    log_level = logging.DEBUG if "--debug" in sys.argv else logging.INFO
    log_file = None
    if "--log" in sys.argv:
        try:
            idx = sys.argv.index("--log")
            log_file = sys.argv[idx + 1]
        except Exception:
            log_file = "scan.log"

    setup_logger(level=log_level, logfile=log_file)

    # --- Detect local IP and subnet ---
    logging.info(f"{now}")
    interface = _first_interface()
    logging.info(f"Interface: {interface}")
    mac = _primary_mac()
    logging.info(f"Local Mac: {mac}")
    local = _local_ip()
    logging.info(f"Local IP: {local}")
    subnet = guess_subnet(local, 24)
    logging.info(f"Guessed subnet: {subnet}")

    # --- Initialize target_ips variable ---
    target_ips = None

# --- Ask user which scan to perform (LAN or custom) ---
MAX_RANGE_SIZE = 512
scan_results = []

# --- Helper functions ---
def _ip_range_from_full_ips(start_ip: str, end_ip: str) -> List[str]:
    a = ipaddress.IPv4Address(start_ip)
    b = ipaddress.IPv4Address(end_ip)
    if int(b) < int(a):
        raise ValueError("End IP is smaller than start IP")
    size = int(b) - int(a) + 1
    if size > MAX_RANGE_SIZE:
        raise ValueError(f"Range too large ({size} IPs); max is {MAX_RANGE_SIZE}")
    return [str(ipaddress.IPv4Address(int(a) + i)) for i in range(size)]

# ---- Main scan loop ----
while True:
    print("\nSelect scan type:")
    print("1 = LAN scanning")
    print("2 = Custom IP range")
    print("3 = Exit")
    scan_mode = input("\nEnter choice: ").strip()

    if scan_mode not in {"1", "2", "3"}:
        print("Invalid choice!")
        continue

    if scan_mode == "1":
        choice = input("\nStart full LAN scan? (Y/N): ").strip().upper()
        if choice not in ("Y", "N"):
            print("Invalid choice!")
            continue
        if choice != "Y":
            print("LAN scan cancelled.")
            input("Press Enter to exit...")
            break

        spinner = Spinner("Running LAN scan")
        spinner.start()
        start = time.time()
        try:
            results = test_print(subnet=subnet, do_port_scan=True, fast=True)
            scan_results.extend(results)
        finally:
            spinner.stop()
            elapsed = time.time() - start
            logging.info(f"LAN scan finished in {elapsed:.1f}s")

    elif scan_mode == "2":
        local_ip = _local_ip()
        print("\nCustom scan options:")
        print("Format options:")
        print(" - Single IP (example: 1.1.1.1)")
        print(" - IP Range  (example: 1.1.1.1-1.1.1.50)\n")

        raw = input("Enter target (single IP or range): ").strip()
        target_ips = []

        try:
            if "-" in raw:
                start_ip, end_ip = map(str.strip, raw.split("-", 1))
                ipaddress.ip_address(start_ip)
                ipaddress.ip_address(end_ip)
                target_ips = _ip_range_from_full_ips(start_ip, end_ip)
            else:
                ipaddress.ip_address(raw)
                target_ips = [raw]
        except Exception as e:
            print(f"Invalid input: {e}")
            continue

        print(f"\nTarget IPs: {len(target_ips)}")
        print(", ".join(target_ips[:10]) + (" ..." if len(target_ips) > 10 else ""))

        choice = input("Start custom scan? (Y/N): ").strip().upper()
        if choice != "Y":
            print("Custom scan cancelled.")
            input("Press Enter to exit...")
            break

        logging.info(f"\nStarting custom scan for {len(target_ips)} targets...")
        scan_results = {}

        # Fixed: remove \n from spinner message
        spinner = Spinner("Running custom scan")
        spinner.start()
        start = time.time()

        try:
            for ip in target_ips:
                # 0 Skip local IP
                if ip == local_ip:
                    logging.info(f"\n[SKIP] {ip} is local — skipping.")
                    continue
                # 1 Only scan private IPs
                if not is_private_ip(ip):
                    logging.info(f"\n[SKIP] {ip} is not private — skipping.")
                    break
                # 2 Ping before scanning
                if not _ping(ip, timeout_ms=400):
                    continue
                # 3 Convert single IP to /32 subnet for test_print
                single_subnet = ipaddress.ip_network(f"{ip}/32")
                # 4 Run silent scan
                try:
                    results = test_print(
                        subnet=single_subnet,
                        do_port_scan=True,
                        fast=True,
                        silent=True
                    )
                except Exception as e:
                    logging.error(f"[ERROR] Scan failed for {ip}: {e}")
                    continue
                # 5 Collect unique results
                if results:
                    for d in results:
                        key = d.get("ip") or d.get("mac")
                        if key and key not in scan_results:
                            scan_results[key] = d
        finally:
            spinner.stop()
            elapsed = time.time() - start
            if scan_results:  # True only if NOT empty
                logging.info(f"Custom scan finished in {elapsed:.1f}s — found {len(scan_results)} devices.")
                print_devices(list(scan_results.values()))
            else:
                print(f"Custom scan finished in {elapsed:.1f}s - No devices found.")

    elif scan_mode == "3":
        input("\nGoodby! Press Enter to exit...")
        sys.exit(0)

    export = input("\nExport logs to text file? (Y to export, Enter to skip): ").strip().lower()
    if export == "y":
        export_path = "scan_log_export.txt"
        with open(export_path, "w", encoding="utf-8") as f:
            f.write(log_buffer.getvalue())
        print(f"Logs exported → {export_path}")
        continue
