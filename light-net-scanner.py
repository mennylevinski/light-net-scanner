#!/usr/bin/env python3
# -*- coding: utf-8 -*-import subprocess

"""
Author: Menny Levinski

Light Network Scanner
Lightweight LAN discovery & port audit tool.

Windows:
python light-net-scanner.py

Linux:
chmod +x light-net-scanner.py
./light-net-scanner.py
"""

import io
import os
import re
import sys
import time
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

# ----------------- Logger Setup -----------------
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

# ----------------- Console helper -----------------
def ensure_console(title: str = "Network Scanner"):
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

# ----------------- Spinner (moving dots) -----------------
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
        # Clear the spinner line when done
        print("\r" + " " * (len(self.message) + 10) + "\r", end="", flush=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        self.thread.join()

# Default common ports to check quickly
COMMON_PORTS = [21, 22, 23, 80, 139, 445, 3389, 5900]  # FTP, SSH, Telnet, HTTP, NetBIOS, SMB, RDP, VNC

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
        s.settimeout(1.0)
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

def _ping(ip: str, timeout_ms: int = 500, rate: int = 10) -> bool:

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
                    ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
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

def _resolve_hostname(ip: str, timeout: float = 2.0) -> str:
    """
    Try to resolve a hostname using:
    1. Reverse DNS
    2. NetBIOS (Linux + Samba tools)
    3. mDNS (Linux + Avahi)
    """

    # 1) Reverse DNS (cross-platform, safest)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            return fut.result(timeout=timeout)[0]
    except Exception:
        pass

    # Linux-only methods here
    if platform.system().lower() == "windows":
        return "-"  # Windows does not have nmblookup/avahi by default

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

    return "-"

def _scan_ports(ip: str, ports: Iterable[int], timeout: float = 0.5, max_workers: int = 100) -> List[int]:
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
        except Exception:
            pass
        return None

    worker_count = min(max_workers, len(ports_list))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as ex:
        futures = {ex.submit(_try_port, p): p for p in ports_list}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)

    return sorted(open_ports)

def discover_hosts(subnet: ipaddress.IPv4Network, max_workers: int = 200, ping_timeout_ms: int = 400) -> List[str]:
    ips = [str(ip) for ip in subnet.hosts()]
    alive = []
    if not ips:
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as ex:
        futures = {ex.submit(_ping, ip, ping_timeout_ms): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    alive.append(ip)
            except Exception:
                pass

    return sorted(alive, key=lambda x: socket.inet_aton(x))

def discover_network(subnet: Optional[ipaddress.IPv4Network] = None,
                     ports: Optional[Iterable[int]] = None,
                     do_port_scan: bool = True,
                     fast: bool = True) -> List[Dict]:
    if ports is None:
        ports = COMMON_PORTS

    local = _local_ip()
    if subnet is None:
        subnet = guess_subnet(local, 24)

    ping_timeout = 300 if fast else 800
    port_timeout = 0.4 if fast else 1.2

    alive_ips = discover_hosts(subnet, ping_timeout_ms=ping_timeout)
    ip_mac = _parse_arp_table()

    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        port_futures = {}
        for ip in alive_ips:
            if do_port_scan:
                port_futures[ip] = ex.submit(_scan_ports, ip, ports, port_timeout, 200)

        for ip in alive_ips:
            hostname = _resolve_hostname(ip, timeout=0.5 if fast else 1.5)
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
    mapping = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        69: "TFTP",
        80: "HTTP",
        139: "NetBIOS",
        161: "SNMP",
        389: "LDAP",
        445: "SMB",
        1433: "MSSQL",
        3389: "RDP",
        5900: "VNC"
    }
    return [f"{p}({mapping.get(p,'')})" if p in mapping else str(p) for p in ports]

# ----------------- Print Setup -----------------
def test_print(subnet: Optional[ipaddress.IPv4Network] = None,
               do_port_scan: bool = True,
               fast: bool = True,
               ports: Optional[Iterable[int]] = None):
    if subnet is None:
        local = _local_ip()
        subnet = guess_subnet(local, 24)

    devices = discover_network(subnet=subnet, do_port_scan=do_port_scan, fast=fast, ports=ports)

    headers = ["IP", "Hostname", "MAC", "Alive", "Open Ports"]
    col_widths = [15, 30, 17, 7, 40]

    def _trim(s: str, w: int) -> str:
        return (s[: w - 3] + "...") if len(s) > w else s

    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_widths))
    sep_line = "-" * len(header_line)

    logging.info(f"Scanned subnet: {subnet} — found {len(devices)} devices")
    logging.info(sep_line)
    logging.info(header_line)
    logging.info(sep_line)

    for d in devices:
        ip = _trim(d["ip"], col_widths[0])
        host = _trim(d["hostname"] or "-", col_widths[1])
        mac = _trim(d["mac"] or "-", col_widths[2])
        alive = str(d["alive"])
        if d["open_ports"]:
            ports_str = ", ".join(_highlight_risky_ports(d["open_ports"]))
        else:
            ports_str = "-"

        logging.info(f"{ip.ljust(col_widths[0])}  {host.ljust(col_widths[1])}  {mac.ljust(col_widths[2])}  {alive.ljust(col_widths[3])}  {ports_str.ljust(col_widths[4])}")

    logging.info(sep_line)

# ----------------- Main -----------------
if __name__ == "__main__":
    ensure_console("Light Network Scanner")

    log_level = logging.DEBUG if "--debug" in sys.argv else logging.INFO
    log_file = None
    if "--log" in sys.argv:
        try:
            idx = sys.argv.index("--log")
            log_file = sys.argv[idx + 1]
        except Exception:
            log_file = "scan.log"

    setup_logger(level=log_level, logfile=log_file)

    # 2) Detect local IP and subnet
    logging.info(f"{now}")
    logging.info("Detecting local IP...")
    local = _local_ip()
    logging.info(f"Local IP: {local}")
    subnet = guess_subnet(local, 24)
    logging.info(f"Guessed subnet: {subnet}")

    # --- Initialize target_ips variable ---
    target_ips = None

    # --- Ask user which scan to perform (robust loop & validation) ---
    MAX_RANGE_SIZE = 512  

    def _ip_range_from_full_ips(start_ip: str, end_ip: str) -> List[str]:
        a = ipaddress.IPv4Address(start_ip)
        b = ipaddress.IPv4Address(end_ip)
        if int(b) < int(a):
            raise ValueError("End IP is smaller than start IP")
        size = int(b) - int(a) + 1
        if size > MAX_RANGE_SIZE:
            raise ValueError(f"Range too large ({size} IPs); max is {MAX_RANGE_SIZE}")
        return [str(ipaddress.IPv4Address(int(a) + i)) for i in range(size)]

    def _ip_range_from_last_octets(base_ip_prefix: str, start_oct: int, end_oct: int) -> List[str]:
        if start_oct < 1 or end_oct > 254 or start_oct > end_oct:
            raise ValueError("Invalid last-octet range; must be 1..254 and start<=end")
        size = end_oct - start_oct + 1
        if size > MAX_RANGE_SIZE:
            raise ValueError(f"Range too large ({size} IPs); max is {MAX_RANGE_SIZE}")
        return [f"{base_ip_prefix}.{i}" for i in range(start_oct, end_oct + 1)]

    # --- User input loop ---
    while True:
        try:
            choice = input("\nScan options:\n1) Entire subnet\n2) Specific range\nSelect 1 or 2: ").strip()
        except KeyboardInterrupt:
            print("\nExiting.")
            sys.exit(0)

        if choice == "1":
            target_ips = None  # full subnet scan
            break

        if choice == "2":
            try:
                range_input = input(
                    "Enter range (last octet only like 100-120, single IP, or full range like 192.168.1.50-192.168.1.80): "
                ).strip()
            except KeyboardInterrupt:
                print("\nExiting.")
                sys.exit(0)

            base_prefix = ".".join(str(subnet.network_address).split(".")[:3])

            try:
                # 1) full-IP range: "192.168.1.50-192.168.1.80" or "192.168.1.50-80"
                if "-" in range_input and "." in range_input:
                    left, right = range_input.split("-", 1)
                    left = left.strip()
                    right = right.strip()
                    if "." not in right:
                        start_ip = ipaddress.IPv4Address(left)
                        end_ip = ipaddress.IPv4Address(".".join(str(start_ip).split(".")[:3]) + "." + right)
                    else:
                        start_ip = ipaddress.IPv4Address(left)
                        end_ip = ipaddress.IPv4Address(right)

                    if ipaddress.IPv4Address(start_ip) not in subnet or ipaddress.IPv4Address(end_ip) not in subnet:
                        raise ValueError("Requested range is outside guessed subnet")

                    target_ips = _ip_range_from_full_ips(str(start_ip), str(end_ip))
                    break

                # 2) last-octet range shorthand: "100-120"
                if "-" in range_input and "." not in range_input:
                    m = re.findall(r"\d+", range_input)
                    if len(m) != 2:
                        raise ValueError("Invalid range format")
                    start_oct, end_oct = map(int, m)
                    target_ips = _ip_range_from_last_octets(base_prefix, start_oct, end_oct)
                    break

                # 3) single full IP: "192.168.1.55"
                if "." in range_input and "-" not in range_input:
                    ip_obj = ipaddress.IPv4Address(range_input)
                    if ip_obj not in subnet:
                        raise ValueError("Requested IP is outside guessed subnet")
                    target_ips = [str(ip_obj)]
                    break

                # 4) single last-octet number: "55"
                if range_input.isdigit():
                    octet = int(range_input)
                    if not (1 <= octet <= 254):
                        raise ValueError("Last octet must be 1..254")
                    target_ips = [f"{base_prefix}.{octet}"]
                    break

                raise ValueError("Unrecognized input format")

            except Exception as err:
                print(f"Invalid range input: {err}\nPlease try again.")
                continue

        print("Please select either '1' or '2'.")
        # loop continues until valid

    # --- Run scan ---
    spinner = Spinner("Running scan")
    spinner.start()
    start = time.time()

    try:
        devices = []

        if target_ips:  # custom IP range
            ip_mac = _parse_arp_table()
            logging.debug(f"Parsed ARP table entries: {len(ip_mac)}")

            # ping and scan logic...
            # (keep your existing threaded scan code here for target_ips)

        else:  # full subnet scan
            test_print(subnet=subnet, do_port_scan=True, fast=True)

    except KeyboardInterrupt:
        logging.warning("Scan cancelled by user (KeyboardInterrupt).")
        print("\nScan cancelled by user.")

    finally:
        spinner.stop()

    # Print results for custom-range scans (test_print already printed for whole-subnet)
    if target_ips:
        headers = ["IP", "Hostname", "MAC", "Alive", "Open Ports"]
        col_widths = [15, 30, 17, 7, 30]
        header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_widths))
        sep_line = "-" * len(header_line)
        print(sep_line)
        print(header_line)
        print(sep_line)
        for d in devices:
            ports_str = ", ".join(_highlight_risky_ports(d["open_ports"])) if d["open_ports"] else "-"
            print(f"{d['ip'].ljust(col_widths[0])}  {(d['hostname'] or '-').ljust(col_widths[1])}  "
                  f"{(d['mac'] or '-').ljust(col_widths[2])}  {str(d['alive']).ljust(col_widths[3])}  {ports_str.ljust(col_widths[4])}")
        print(sep_line)

    elapsed = time.time() - start
    logging.info(f"Scan finished in {elapsed:.1f}s")

    # ----------------- Optional export -----------------
    choice = input("\nExport logs to text file? (Y to export, Enter to skip): ").strip().lower()
    if choice == "y":
        export_path = "scan_log_export.txt"
        with open(export_path, "w", encoding="utf-8") as f:
            f.write(log_buffer.getvalue())
        print(f"Logs exported → {export_path}")

    input("\nScan finished! Press Enter to exit...")
