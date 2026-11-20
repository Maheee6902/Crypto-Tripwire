"""Phase 2: Fast, independent, and verifiable volatile evidence capture & integrity verification."""

from __future__ import annotations

import csv
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple
import time

from crypto_tripwire import SCHEMA_VERSION, __version__
from crypto_tripwire.config import AppConfig, CaptureSettings
from crypto_tripwire.entropy import utc_now_iso
from crypto_tripwire.models import (
    ManifestArtifactEntry,
    MonitoredFileEvent,
    ProviderMetadata,
    ProviderStatus,
    TriggerRecord,
    VerificationItemResult,
    VerificationReport,
    VerificationStatus,
)


def atomic_write_bytes(target_path: Path, data: bytes) -> Tuple[int, str]:
    """Write bytes to a temporary sibling file, fsync, and atomically rename into place."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_name(f".{target_path.name}.tmp_{os.getpid()}_{time.monotonic_ns()}")
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, target_path)
    digest = hashlib.sha256(data).hexdigest()
    return len(data), digest


def atomic_write_json(target_path: Path, payload: Any) -> Tuple[int, str]:
    data = json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=False).encode("utf-8")
    return atomic_write_bytes(target_path, data)


def compute_file_sha256(filepath: Path) -> Tuple[int, str]:
    h = hashlib.sha256()
    total = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            total += len(chunk)
            h.update(chunk)
    return total, h.hexdigest()


class ProcessProvider:
    """Collects running process snapshot using `psutil` when available or platform-native fallbacks (`/proc` or `tasklist`)."""

    def collect(self, case_dir: Path) -> Tuple[ProviderMetadata, ManifestArtifactEntry]:
        start_utc = utc_now_iso()
        start_ns = time.monotonic_ns()
        errors: List[str] = []
        processes: List[Dict[str, Any]] = []
        provider_version = "stdlib_fallback"

        try:
            import psutil  # type: ignore

            provider_version = f"psutil_{getattr(psutil, '__version__', 'unknown')}"
            for p in psutil.process_iter(["pid", "ppid", "name", "create_time", "exe", "cmdline", "username"]):
                try:
                    info = p.info
                    ctime_raw = info.get("create_time")
                    ctime_utc: Optional[str] = None
                    if isinstance(ctime_raw, (int, float)) and ctime_raw > 0:
                        ctime_utc = (
                            datetime.datetime.fromtimestamp(ctime_raw, tz=datetime.timezone.utc)
                            .isoformat()
                            .replace("+00:00", "Z")
                        )
                    cmdline_val = info.get("cmdline")
                    if isinstance(cmdline_val, list):
                        cmdline_str: Optional[str] = " ".join(str(x) for x in cmdline_val) if cmdline_val else None
                    else:
                        cmdline_str = str(cmdline_val) if cmdline_val else None
                    processes.append(
                        {
                            "pid": info.get("pid"),
                            "ppid": info.get("ppid"),
                            "name": info.get("name") or "unknown",
                            "create_time_utc": ctime_utc,
                            "create_time_status": "AVAILABLE" if ctime_utc else "UNAVAILABLE",
                            "exe": info.get("exe"),
                            "cmdline": cmdline_str,
                            "username": info.get("username"),
                            "access_status": "OK",
                        }
                    )
                except psutil.NoSuchProcess as exc:
                    errors.append(f"Process exited during enumeration (PID={getattr(exc, 'pid', '?')}).")
                except psutil.AccessDenied as exc:
                    pid_val = getattr(exc, "pid", None)
                    processes.append(
                        {
                            "pid": pid_val,
                            "ppid": None,
                            "name": getattr(p, "name", lambda: "access_denied")() if hasattr(p, "name") else "access_denied",
                            "create_time_utc": None,
                            "create_time_status": "ACCESS_DENIED",
                            "exe": None,
                            "cmdline": None,
                            "username": None,
                            "access_status": "ACCESS_DENIED",
                        }
                    )
                    errors.append(f"AccessDenied reading process details (PID={pid_val}).")
                except Exception as exc:
                    errors.append(f"Unexpected process enumeration error: {type(exc).__name__}: {exc}")
        except ImportError:
            if os.name == "posix" and os.path.isdir("/proc"):
                provider_version = "linux_procfs_native"
                processes, errors = self._collect_linux_procfs()
            elif os.name == "nt":
                provider_version = "windows_tasklist_native"
                processes, errors = self._collect_windows_tasklist()
            else:
                errors.append("Neither psutil nor supported native process interface (/proc or tasklist) was available.")

        end_utc = utc_now_iso()
        dur_ms = round((time.monotonic_ns() - start_ns) / 1_000_000.0, 4)

        if processes:
            status = ProviderStatus.PARTIAL.value if errors else ProviderStatus.SUCCESS.value
        else:
            status = ProviderStatus.FAILED.value if errors else ProviderStatus.ZERO_RECORDS.value

        rel_path = "processes.json"
        payload = {
            "schema_version": SCHEMA_VERSION,
            "captured_utc": start_utc,
            "completed_utc": end_utc,
            "provider_version": provider_version,
            "provider_status": status,
            "record_count": len(processes),
            "error_count": len(errors),
            "errors": errors,
            "processes": processes,
        }
        size_b, digest = atomic_write_json(case_dir / rel_path, payload)

        meta = ProviderMetadata(
            provider_name="process_snapshot",
            start_utc=start_utc,
            end_utc=end_utc,
            duration_ms=dur_ms,
            status=status,
            record_count=len(processes),
            tool_or_provider_version=provider_version,
            errors=errors,
            artifact_relpath=rel_path,
        )
        manifest_entry = ManifestArtifactEntry(
            relative_path=rel_path,
            size_bytes=size_b,
            sha256=digest,
            acquisition_start_utc=start_utc,
            acquisition_end_utc=end_utc,
            acquisition_duration_ms=dur_ms,
            schema_version=SCHEMA_VERSION,
            provider_name="process_snapshot",
            provider_status=status,
        )
        return meta, manifest_entry

    def _collect_linux_procfs(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        procs: List[Dict[str, Any]] = []
        errors: List[str] = []
        clk_tck = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK")) if hasattr(os, "sysconf") else 100
        btime_epoch: Optional[float] = None
        try:
            with open("/proc/stat", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("btime "):
                        btime_epoch = float(line.split()[1])
                        break
        except OSError as exc:
            errors.append(f"Could not read /proc/stat btime: {exc}")

        try:
            entries = [d for d in os.listdir("/proc") if d.isdigit()]
        except OSError as exc:
            return [], [f"Failed listing /proc: {exc}"]

        for pid_str in entries:
            pid = int(pid_str)
            pdir = Path("/proc") / pid_str
            try:
                with open(pdir / "stat", "r", encoding="utf-8", errors="replace") as f:
                    stat_raw = f.read().strip()
                rparen = stat_raw.rfind(")")
                lparen = stat_raw.find("(")
                name = stat_raw[lparen + 1 : rparen] if (lparen != -1 and rparen != -1) else "unknown"
                rest = stat_raw[rparen + 2 :].split()
                ppid = int(rest[1]) if len(rest) > 1 else None
                start_ticks = int(rest[19]) if len(rest) > 19 else None

                ctime_utc: Optional[str] = None
                if btime_epoch is not None and start_ticks is not None and clk_tck > 0:
                    c_epoch = btime_epoch + (start_ticks / float(clk_tck))
                    ctime_utc = (
                        datetime.datetime.fromtimestamp(c_epoch, tz=datetime.timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                    )

                cmdline_str: Optional[str] = None
                try:
                    with open(pdir / "cmdline", "rb") as cf:
                        raw_cmd = cf.read(4096)
                    if raw_cmd:
                        parts = [p.decode("utf-8", errors="replace") for p in raw_cmd.rstrip(b"\x00").split(b"\x00")]
                        cmdline_str = " ".join(parts)
                except OSError:
                    cmdline_str = None

                exe_str: Optional[str] = None
                try:
                    exe_str = os.readlink(pdir / "exe")
                except OSError:
                    exe_str = None

                procs.append(
                    {
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "create_time_utc": ctime_utc,
                        "create_time_status": "AVAILABLE" if ctime_utc else "UNAVAILABLE",
                        "exe": exe_str,
                        "cmdline": cmdline_str,
                        "username": None,
                        "access_status": "OK",
                    }
                )
            except FileNotFoundError:
                errors.append(f"Process PID={pid} vanished during /proc enumeration.")
            except PermissionError:
                procs.append(
                    {
                        "pid": pid,
                        "ppid": None,
                        "name": "access_denied",
                        "create_time_utc": None,
                        "create_time_status": "ACCESS_DENIED",
                        "exe": None,
                        "cmdline": None,
                        "username": None,
                        "access_status": "ACCESS_DENIED",
                    }
                )
                errors.append(f"PermissionDenied reading /proc/{pid}.")
            except Exception as exc:
                errors.append(f"Error reading /proc/{pid}: {type(exc).__name__}: {exc}")

        return procs, errors

    def _collect_windows_tasklist(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        procs: List[Dict[str, Any]] = []
        errors: List[str] = []
        try:
            cp = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=15.0,
                check=False,
            )
            if cp.returncode != 0:
                errors.append(f"tasklist exited with code {cp.returncode}: {cp.stderr.strip()}")
                return [], errors
            reader = csv.reader(cp.stdout.splitlines())
            for row in reader:
                if len(row) >= 2 and row[1].isdigit():
                    procs.append(
                        {
                            "pid": int(row[1]),
                            "ppid": None,
                            "name": row[0],
                            "create_time_utc": None,
                            "create_time_status": "UNAVAILABLE_IN_TASKLIST_FALLBACK",
                            "exe": None,
                            "cmdline": None,
                            "username": None,
                            "access_status": "OK",
                        }
                    )
        except Exception as exc:
            errors.append(f"tasklist execution failed: {type(exc).__name__}: {exc}")
        return procs, errors


class NetworkProvider:
    """
    Collects active network socket snapshot without inferring connection initiation direction.
    Uses `psutil` when available or `/proc/net/{tcp,tcp6,udp,udp6}` / `netstat -ano` as fallback.
    """

    def collect(self, case_dir: Path) -> Tuple[ProviderMetadata, ManifestArtifactEntry]:
        start_utc = utc_now_iso()
        start_ns = time.monotonic_ns()
        errors: List[str] = []
        connections: List[Dict[str, Any]] = []
        provider_version = "stdlib_fallback"

        try:
            import psutil  # type: ignore

            provider_version = f"psutil_{getattr(psutil, '__version__', 'unknown')}"
            try:
                raw_conns = psutil.net_connections(kind="inet")
                for c in raw_conns:
                    try:
                        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                        connections.append(
                            {
                                "laddr": laddr,
                                "raddr": raddr,
                                "status": str(c.status or "NONE"),
                                "pid": c.pid,
                                "direction_inference": "UNKNOWN_FROM_SNAPSHOT_ALONE",
                                "observed_at_utc": start_utc,
                            }
                        )
                    except Exception as item_exc:
                        errors.append(f"Socket entry parse error: {type(item_exc).__name__}: {item_exc}")
            except Exception as prov_exc:
                errors.append(f"psutil.net_connections failed: {type(prov_exc).__name__}: {prov_exc}")
        except ImportError:
            if os.name == "posix" and os.path.isdir("/proc/net"):
                provider_version = "linux_proc_net_native"
                connections, errors = self._collect_linux_proc_net(start_utc)
            elif os.name == "nt":
                provider_version = "windows_netstat_native"
                connections, errors = self._collect_windows_netstat(start_utc)
            else:
                errors.append("Neither psutil nor supported native socket interface was available.")

        end_utc = utc_now_iso()
        dur_ms = round((time.monotonic_ns() - start_ns) / 1_000_000.0, 4)

        if connections:
            status = ProviderStatus.PARTIAL.value if errors else ProviderStatus.SUCCESS.value
        else:
            status = ProviderStatus.FAILED.value if errors else ProviderStatus.ZERO_RECORDS.value

        rel_path = "network.json"
        payload = {
            "schema_version": SCHEMA_VERSION,
            "captured_utc": start_utc,
            "completed_utc": end_utc,
            "provider_version": provider_version,
            "provider_status": status,
            "record_count": len(connections),
            "error_count": len(errors),
            "errors": errors,
            "direction_semantics_note": (
                "A point-in-time socket table snapshot does not record which endpoint initiated the TCP handshake; "
                "direction_inference is explicitly preserved as UNKNOWN_FROM_SNAPSHOT_ALONE."
            ),
            "connections": connections,
        }
        size_b, digest = atomic_write_json(case_dir / rel_path, payload)

        meta = ProviderMetadata(
            provider_name="network_snapshot",
            start_utc=start_utc,
            end_utc=end_utc,
            duration_ms=dur_ms,
            status=status,
            record_count=len(connections),
            tool_or_provider_version=provider_version,
            errors=errors,
            artifact_relpath=rel_path,
        )
        manifest_entry = ManifestArtifactEntry(
            relative_path=rel_path,
            size_bytes=size_b,
            sha256=digest,
            acquisition_start_utc=start_utc,
            acquisition_end_utc=end_utc,
            acquisition_duration_ms=dur_ms,
            schema_version=SCHEMA_VERSION,
            provider_name="network_snapshot",
            provider_status=status,
        )
        return meta, manifest_entry

    def _collect_linux_proc_net(self, observed_utc: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        conns: List[Dict[str, Any]] = []
        errors: List[str] = []
        tcp_states = {
            "01": "ESTABLISHED",
            "02": "SYN_SENT",
            "03": "SYN_RECV",
            "04": "FIN_WAIT1",
            "05": "FIN_WAIT2",
            "06": "TIME_WAIT",
            "07": "CLOSE",
            "08": "CLOSE_WAIT",
            "09": "LAST_ACK",
            "0A": "LISTEN",
            "0B": "CLOSING",
        }
        # Map socket inode -> pid when readable
        inode_to_pid: Dict[str, int] = {}
        try:
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                fd_dir = Path("/proc") / pid_str / "fd"
                try:
                    for fd_name in os.listdir(fd_dir):
                        try:
                            target = os.readlink(fd_dir / fd_name)
                            if target.startswith("socket:[") and target.endswith("]"):
                                ino = target[8:-1]
                                inode_to_pid[ino] = int(pid_str)
                        except OSError:
                            continue
                except OSError:
                    continue
        except OSError:
            pass

        for proto, is_v6 in [("tcp", False), ("tcp6", True), ("udp", False), ("udp6", True)]:
            pfile = Path("/proc/net") / proto
            if not pfile.exists():
                continue
            try:
                with open(pfile, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    l_ip_Port = self._decode_proc_endpoint(parts[1], is_v6)
                    r_ip_Port = self._decode_proc_endpoint(parts[2], is_v6)
                    st_code = parts[3].upper()
                    status = tcp_states.get(st_code, f"STATE_{st_code}")
                    ino = parts[9]
                    conns.append(
                        {
                            "laddr": l_ip_Port,
                            "raddr": "" if r_ip_Port.startswith(("0.0.0.0:0", "[::]:0")) else r_ip_Port,
                            "status": status,
                            "pid": inode_to_pid.get(ino),
                            "protocol": proto,
                            "direction_inference": "UNKNOWN_FROM_SNAPSHOT_ALONE",
                            "observed_at_utc": observed_utc,
                        }
                    )
            except OSError as exc:
                errors.append(f"Error reading {pfile}: {exc}")

        return conns, errors

    @staticmethod
    def _decode_proc_endpoint(hex_ep: str, is_v6: bool) -> str:
        try:
            addr_hex, port_hex = hex_ep.split(":")
            port = int(port_hex, 16)
            if not is_v6:
                ip_int = int(addr_hex, 16)
                ip_bytes = ip_int.to_bytes(4, byteorder="little")
                ip_str = socket.inet_ntop(socket.AF_INET, ip_bytes)
                return f"{ip_str}:{port}"
            raw_b = bytes.fromhex(addr_hex)
            # Linux /proc/net/tcp6 stores 4 little-endian 32-bit words
            reordered = b"".join(raw_b[i : i + 4][::-1] for i in range(0, 16, 4))
            ip_str = socket.inet_ntop(socket.AF_INET6, reordered)
            return f"[{ip_str}]:{port}"
        except Exception:
            return hex_ep

    def _collect_windows_netstat(self, observed_utc: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        conns: List[Dict[str, Any]] = []
        errors: List[str] = []
        try:
            cp = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=15.0,
                check=False,
            )
            if cp.returncode != 0:
                errors.append(f"netstat exited with code {cp.returncode}: {cp.stderr.strip()}")
                return [], errors
            for line in cp.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0].upper() in ("TCP", "UDP"):
                    proto = parts[0].upper()
                    laddr = parts[1]
                    raddr = "" if parts[2] in ("*:*", "0.0.0.0:0", "[::]:0") else parts[2]
                    status = parts[3] if proto == "TCP" else "STATELESS_UDP"
                    pid_str = parts[4] if proto == "TCP" else parts[3]
                    conns.append(
                        {
                            "laddr": laddr,
                            "raddr": raddr,
                            "status": status,
                            "pid": int(pid_str) if pid_str.isdigit() else None,
                            "protocol": proto.lower(),
                            "direction_inference": "UNKNOWN_FROM_SNAPSHOT_ALONE",
                            "observed_at_utc": observed_utc,
                        }
                    )
        except Exception as exc:
            errors.append(f"netstat failed: {type(exc).__name__}: {exc}")
        return conns, errors


class MemoryAcquisitionProvider:
    """
    Optional volatile memory acquisition adapter supporting:
    1. Live execution of an institution-installed acquisition tool (e.g., Velocidex WinPmem)
       using a fixed argument list (never shell interpolation).
    2. Importing an existing analyst-acquired memory image with explicit provenance.
    3. Clean UNAVAILABLE status when neither is configured or available, without creating
       fake/empty RAM files or mislabeling process JSON as a memory dump.
    """

    def __init__(self, settings: CaptureSettings) -> None:
        self.settings = settings

    def acquire_or_import(self, case_dir: Path) -> Tuple[ProviderMetadata, Optional[ManifestArtifactEntry], Dict[str, Any]]:
        start_utc = utc_now_iso()
        start_ns = time.monotonic_ns()
        errors: List[str] = []

        # Path 1: Analyst-imported image
        if self.settings.imported_ram_image_path:
            imp_path = Path(self.settings.imported_ram_image_path)
            if not imp_path.exists() or not imp_path.is_file():
                errors.append(f"Configured imported_ram_image_path does not exist: {imp_path}")
                return self._build_result(
                    case_dir=case_dir,
                    start_utc=start_utc,
                    start_ns=start_ns,
                    status=ProviderStatus.FAILED.value,
                    tool_version="analyst_import_adapter",
                    errors=errors,
                    provenance="analyst_imported_missing",
                    image_relpath=None,
                    image_size=0,
                    image_sha256=None,
                    exit_code=None,
                )
            fsize, fhash = compute_file_sha256(imp_path)
            if fsize == 0:
                errors.append(f"Imported RAM image is 0 bytes (rejected as empty): {imp_path}")
                return self._build_result(
                    case_dir=case_dir,
                    start_utc=start_utc,
                    start_ns=start_ns,
                    status=ProviderStatus.FAILED.value,
                    tool_version="analyst_import_adapter",
                    errors=errors,
                    provenance="analyst_imported_empty_rejected",
                    image_relpath=None,
                    image_size=0,
                    image_sha256=None,
                    exit_code=None,
                )

            provenance_note = (
                self.settings.imported_ram_provenance
                or "Analyst-acquired memory image imported into case record (not captured live by this tool run)."
            )
            return self._build_result(
                case_dir=case_dir,
                start_utc=start_utc,
                start_ns=start_ns,
                status=ProviderStatus.IMPORTED.value,
                tool_version="analyst_import_adapter",
                errors=errors,
                provenance=provenance_note,
                image_relpath=str(imp_path.resolve()),
                image_size=fsize,
                image_sha256=fhash,
                exit_code=0,
                is_external_reference=True,
            )

        # Path 2: Live acquisition disabled
        if not self.settings.enable_ram_acquisition:
            return self._build_result(
                case_dir=case_dir,
                start_utc=start_utc,
                start_ns=start_ns,
                status=ProviderStatus.UNAVAILABLE.value,
                tool_version="disabled_in_config",
                errors=[],
                provenance="Optional live RAM acquisition disabled in configuration (enable_ram_acquisition=false).",
                image_relpath=None,
                image_size=0,
                image_sha256=None,
                exit_code=None,
            )

        # Path 3: Live acquisition enabled -> validate executable, disk space, permissions
        exe_str = self.settings.ram_tool_executable
        if not exe_str:
            errors.append("enable_ram_acquisition=true but ram_tool_executable is not configured.")
            return self._build_result(
                case_dir=case_dir,
                start_utc=start_utc,
                start_ns=start_ns,
                status=ProviderStatus.UNAVAILABLE.value,
                tool_version="unconfigured_executable",
                errors=errors,
                provenance="No acquisition executable configured.",
                image_relpath=None,
                image_size=0,
                image_sha256=None,
                exit_code=None,
            )

        exe_path = Path(exe_str)
        if not exe_path.exists() or not exe_path.is_file():
            errors.append(f"Configured RAM acquisition executable not found: {exe_path}")
            return self._build_result(
                case_dir=case_dir,
                start_utc=start_utc,
                start_ns=start_ns,
                status=ProviderStatus.UNAVAILABLE.value,
                tool_version=str(exe_path.name),
                errors=errors,
                provenance="Acquisition tool binary absent on host.",
                image_relpath=None,
                image_size=0,
                image_sha256=None,
                exit_code=None,
            )

        # Check free disk space
        try:
            usage = shutil.disk_usage(case_dir)
            free_mb = usage.free // (1024 * 1024)
            if free_mb < self.settings.ram_min_free_disk_mb:
                errors.append(
                    f"Insufficient free disk space for RAM dump ({free_mb} MB available < "
                    f"{self.settings.ram_min_free_disk_mb} MB required)."
                )
                return self._build_result(
                    case_dir=case_dir,
                    start_utc=start_utc,
                    start_ns=start_ns,
                    status=ProviderStatus.FAILED.value,
                    tool_version=str(exe_path.name),
                    errors=errors,
                    provenance="Aborted before invocation due to disk space threshold.",
                    image_relpath=None,
                    image_size=0,
                    image_sha256=None,
                    exit_code=None,
                )
        except OSError as exc:
            errors.append(f"Disk space check warning: {exc}")

        raw_relpath = "memory_dump.raw"
        raw_target = case_dir / raw_relpath
        # Fixed argument structure: [executable, output_path] (standard Velocidex WinPmem CLI syntax: `winpmem_mini_x64.exe physmem.raw`)
        cmd_args = [str(exe_path.resolve()), str(raw_target.resolve())]

        try:
            cp = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=self.settings.ram_timeout_seconds,
                shell=False,
                check=False,
            )
            if cp.returncode != 0:
                errors.append(f"Acquisition tool exited with status {cp.returncode}: {cp.stderr.strip() or cp.stdout.strip()}")
                if raw_target.exists():
                    inc_size, inc_hash = compute_file_sha256(raw_target)
                    inc_rel = "memory_dump.incomplete.raw"
                    os.replace(raw_target, case_dir / inc_rel)
                    return self._build_result(
                        case_dir=case_dir,
                        start_utc=start_utc,
                        start_ns=start_ns,
                        status=ProviderStatus.FAILED.value,
                        tool_version=str(exe_path.name),
                        errors=errors,
                        provenance="Live acquisition failed; partial file retained as incomplete.",
                        image_relpath=inc_rel,
                        image_size=inc_size,
                        image_sha256=inc_hash,
                        exit_code=cp.returncode,
                    )
                return self._build_result(
                    case_dir=case_dir,
                    start_utc=start_utc,
                    start_ns=start_ns,
                    status=ProviderStatus.FAILED.value,
                    tool_version=str(exe_path.name),
                    errors=errors,
                    provenance="Live acquisition failed with no output image.",
                    image_relpath=None,
                    image_size=0,
                    image_sha256=None,
                    exit_code=cp.returncode,
                )

            if not raw_target.exists():
                errors.append("Acquisition tool returned 0 but output file was not created.")
                return self._build_result(
                    case_dir=case_dir,
                    start_utc=start_utc,
                    start_ns=start_ns,
                    status=ProviderStatus.FAILED.value,
                    tool_version=str(exe_path.name),
                    errors=errors,
                    provenance="Tool produced no output file.",
                    image_relpath=None,
                    image_size=0,
                    image_sha256=None,
                    exit_code=cp.returncode,
                )

            img_size, img_hash = compute_file_sha256(raw_target)
            if img_size == 0:
                raw_target.unlink(missing_ok=True)
                errors.append("Acquisition tool produced an empty (0-byte) file; rejected as unsuccessful.")
                return self._build_result(
                    case_dir=case_dir,
                    start_utc=start_utc,
                    start_ns=start_ns,
                    status=ProviderStatus.FAILED.value,
                    tool_version=str(exe_path.name),
                    errors=errors,
                    provenance="Rejected 0-byte RAM dump.",
                    image_relpath=None,
                    image_size=0,
                    image_sha256=None,
                    exit_code=cp.returncode,
                )

            return self._build_result(
                case_dir=case_dir,
                start_utc=start_utc,
                start_ns=start_ns,
                status=ProviderStatus.SUCCESS.value,
                tool_version=str(exe_path.name),
                errors=errors,
                provenance="Captured live by Crypto-Tripwire via configured acquisition binary.",
                image_relpath=raw_relpath,
                image_size=img_size,
                image_sha256=img_hash,
                exit_code=cp.returncode,
            )

        except subprocess.TimeoutExpired:
            errors.append(f"RAM acquisition timed out after {self.settings.ram_timeout_seconds}s.")
            inc_rel = None
            inc_size = 0
            inc_hash = None
            if raw_target.exists():
                inc_size, inc_hash = compute_file_sha256(raw_target)
                inc_rel = "memory_dump.incomplete.raw"
                os.replace(raw_target, case_dir / inc_rel)
            return self._build_result(
                case_dir=case_dir,
                start_utc=start_utc,
                start_ns=start_ns,
                status=ProviderStatus.TIMEOUT.value,
                tool_version=str(exe_path.name),
                errors=errors,
                provenance="Live acquisition timed out; partial file marked incomplete.",
                image_relpath=inc_rel,
                image_size=inc_size,
                image_sha256=inc_hash,
                exit_code=None,
            )
        except Exception as exc:
            errors.append(f"Error invoking RAM acquisition tool: {type(exc).__name__}: {exc}")
            return self._build_result(
                case_dir=case_dir,
                start_utc=start_utc,
                start_ns=start_ns,
                status=ProviderStatus.FAILED.value,
                tool_version=str(exe_path.name),
                errors=errors,
                provenance="Exception during live RAM acquisition.",
                image_relpath=None,
                image_size=0,
                image_sha256=None,
                exit_code=None,
            )

    def _build_result(
        self,
        case_dir: Path,
        start_utc: str,
        start_ns: int,
        status: str,
        tool_version: str,
        errors: List[str],
        provenance: str,
        image_relpath: Optional[str],
        image_size: int,
        image_sha256: Optional[str],
        exit_code: Optional[int],
        is_external_reference: bool = False,
    ) -> Tuple[ProviderMetadata, Optional[ManifestArtifactEntry], Dict[str, Any]]:
        end_utc = utc_now_iso()
        dur_ms = round((time.monotonic_ns() - start_ns) / 1_000_000.0, 4)

        status_record = {
            "schema_version": SCHEMA_VERSION,
            "provider_name": "memory_acquisition",
            "acquisition_start_utc": start_utc,
            "acquisition_end_utc": end_utc,
            "duration_ms": dur_ms,
            "status": status,
            "tool_version": tool_version,
            "provenance": provenance,
            "is_external_reference": is_external_reference,
            "image_path": image_relpath,
            "image_size_bytes": image_size,
            "image_sha256": image_sha256,
            "exit_code": exit_code,
            "errors": errors,
        }
        status_rel = "memory_acquisition.json"
        s_size, s_digest = atomic_write_json(case_dir / status_rel, status_record)

        meta = ProviderMetadata(
            provider_name="memory_acquisition",
            start_utc=start_utc,
            end_utc=end_utc,
            duration_ms=dur_ms,
            status=status,
            record_count=1 if status in (ProviderStatus.SUCCESS.value, ProviderStatus.IMPORTED.value) else 0,
            tool_or_provider_version=tool_version,
            errors=errors,
            notes=provenance,
            artifact_relpath=status_rel,
        )
        manifest_entry = ManifestArtifactEntry(
            relative_path=status_rel,
            size_bytes=s_size,
            sha256=s_digest,
            acquisition_start_utc=start_utc,
            acquisition_end_utc=end_utc,
            acquisition_duration_ms=dur_ms,
            schema_version=SCHEMA_VERSION,
            provider_name="memory_acquisition",
            provider_status=status,
        )
        return meta, manifest_entry, status_record


class EvidenceCaptureCoordinator:
    """
    Executes Phase 2 evidence preservation in a dedicated per-incident case directory:
    1. Immediately writes trigger.json and pre_alert_events.json.
    2. Runs fast process and network snapshots independently (one failure never erases another).
    3. Runs optional memory acquisition adapter.
    4. Writes finalized capture_manifest.json (and legacy-compatible manifest.json) without self-hashing circularity.
    """

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.proc_provider = ProcessProvider()
        self.net_provider = NetworkProvider()
        self.mem_provider = MemoryAcquisitionProvider(config.capture)

    def capture_case(
        self,
        trigger: TriggerRecord,
        pre_alert_events: List[MonitoredFileEvent],
    ) -> Tuple[Path, Dict[str, Any]]:
        capture_start_utc = utc_now_iso()
        capture_start_ns = time.monotonic_ns()
        trigger_to_capture_delay_ms = round(
            max(0.0, (capture_start_ns - trigger.trigger_monotonic_ns) / 1_000_000.0), 4
        )

        case_dir = Path(self.config.output_root) / trigger.case_id
        case_dir.mkdir(parents=True, exist_ok=False)

        artifacts: List[ManifestArtifactEntry] = []
        providers: List[ProviderMetadata] = []

        # 1. Preserve trigger and pre-alert observations immediately
        t_start_utc = utc_now_iso()
        t_start_ns = time.monotonic_ns()
        trig_size, trig_sha = atomic_write_json(case_dir / "trigger.json", trigger.to_dict())
        t_end_utc = utc_now_iso()
        t_dur_ms = round((time.monotonic_ns() - t_start_ns) / 1_000_000.0, 4)
        artifacts.append(
            ManifestArtifactEntry(
                relative_path="trigger.json",
                size_bytes=trig_size,
                sha256=trig_sha,
                acquisition_start_utc=t_start_utc,
                acquisition_end_utc=t_end_utc,
                acquisition_duration_ms=t_dur_ms,
                schema_version=SCHEMA_VERSION,
                provider_name="phase1_trigger_record",
                provider_status=ProviderStatus.SUCCESS.value,
            )
        )

        pa_start_utc = utc_now_iso()
        pa_start_ns = time.monotonic_ns()
        pa_payload = {
            "schema_version": SCHEMA_VERSION,
            "case_id": trigger.case_id,
            "recorded_utc": pa_start_utc,
            "event_count": len(pre_alert_events),
            "events": [e.to_dict() for e in pre_alert_events],
        }
        pa_size, pa_sha = atomic_write_json(case_dir / "pre_alert_events.json", pa_payload)
        pa_end_utc = utc_now_iso()
        pa_dur_ms = round((time.monotonic_ns() - pa_start_ns) / 1_000_000.0, 4)
        artifacts.append(
            ManifestArtifactEntry(
                relative_path="pre_alert_events.json",
                size_bytes=pa_size,
                sha256=pa_sha,
                acquisition_start_utc=pa_start_utc,
                acquisition_end_utc=pa_end_utc,
                acquisition_duration_ms=pa_dur_ms,
                schema_version=SCHEMA_VERSION,
                provider_name="phase1_pre_alert_buffer",
                provider_status=ProviderStatus.SUCCESS.value,
            )
        )

        # 2. Quick volatile snapshots (Processes and Network)
        if self.config.capture.collect_processes:
            p_meta, p_art = self.proc_provider.collect(case_dir)
            providers.append(p_meta)
            artifacts.append(p_art)

        if self.config.capture.collect_network:
            n_meta, n_art = self.net_provider.collect(case_dir)
            providers.append(n_meta)
            artifacts.append(n_art)

        # 3. Optional memory acquisition (isolated after quick snapshots)
        m_meta, m_art, m_record = self.mem_provider.acquire_or_import(case_dir)
        providers.append(m_meta)
        if m_art is not None:
            artifacts.append(m_art)
        # If a live image file was written inside case_dir, include it in manifest artifacts too
        img_rel = m_record.get("image_path")
        if img_rel and not m_record.get("is_external_reference") and (case_dir / img_rel).exists():
            artifacts.append(
                ManifestArtifactEntry(
                    relative_path=img_rel,
                    size_bytes=int(m_record["image_size_bytes"]),
                    sha256=str(m_record["image_sha256"]),
                    acquisition_start_utc=m_meta.start_utc,
                    acquisition_end_utc=m_meta.end_utc,
                    acquisition_duration_ms=m_meta.duration_ms,
                    schema_version="raw_binary",
                    provider_name="memory_acquisition_binary",
                    provider_status=m_meta.status,
                )
            )

        capture_end_utc = utc_now_iso()
        capture_total_ms = round((time.monotonic_ns() - capture_start_ns) / 1_000_000.0, 4)

        # 4. Write finalized capture manifest (never hashes itself)
        hashes_map = {a.relative_path: a.sha256 for a in artifacts}
        manifest_payload = {
            "schema_version": SCHEMA_VERSION,
            "application_version": __version__,
            "case_id": trigger.case_id,
            "timestamp": capture_start_utc,
            "capture_start_utc": capture_start_utc,
            "capture_end_utc": capture_end_utc,
            "capture_duration_ms": capture_total_ms,
            "trigger_to_capture_delay_ms": trigger_to_capture_delay_ms,
            "hashes": hashes_map,
            "artifacts": [a.to_dict() for a in artifacts],
            "providers": [p.to_dict() for p in providers],
            "integrity_note": (
                "Manifest hashes cover exact finalized bytes of each listed evidence artifact. "
                "The manifest does not hash itself; downstream Phase 3 and Phase 4 artifacts record "
                "the SHA-256 digest of this manifest.json."
            ),
        }
        _, manifest_sha = atomic_write_json(case_dir / "manifest.json", manifest_payload)
        manifest_payload["manifest_sha256_reference"] = manifest_sha
        return case_dir, manifest_payload


def verify_case_manifest(case_dir: str | os.PathLike[str], manifest_filename: str = "manifest.json") -> VerificationReport:
    """
    Independently recompute SHA-256 and byte sizes of all artifacts listed in `manifest.json`
    (supporting both v2.0 `artifacts` list and legacy v1.0 `hashes` dictionary).
    """
    cpath = Path(case_dir)
    mpath = cpath / manifest_filename
    verified_utc = utc_now_iso()
    case_id = cpath.name

    if not mpath.exists():
        return VerificationReport(
            case_id=case_id,
            verified_utc=verified_utc,
            manifest_relpath=manifest_filename,
            manifest_sha256=None,
            overall_status=VerificationStatus.MANIFEST_MISSING.value,
            schema_version="unknown",
            checked_count=0,
            verified_count=0,
            mismatch_count=0,
            missing_count=0,
            items=[],
            notes=[f"Manifest file {manifest_filename} is missing in {cpath}."],
        )

    try:
        _, manifest_sha = compute_file_sha256(mpath)
        with open(mpath, "r", encoding="utf-8") as f:
            mdata = json.load(f)
    except Exception as exc:
        return VerificationReport(
            case_id=case_id,
            verified_utc=verified_utc,
            manifest_relpath=manifest_filename,
            manifest_sha256=None,
            overall_status=VerificationStatus.MANIFEST_INVALID.value,
            schema_version="invalid",
            checked_count=0,
            verified_count=0,
            mismatch_count=0,
            missing_count=0,
            items=[],
            notes=[f"Failed to parse {manifest_filename}: {type(exc).__name__}: {exc}"],
        )

    schema_ver = str(mdata.get("schema_version", "1.0_legacy"))
    case_id = str(mdata.get("case_id", case_id))
    expected_entries: List[Tuple[str, str, Optional[int]]] = []

    if "artifacts" in mdata and isinstance(mdata["artifacts"], list):
        for art in mdata["artifacts"]:
            rel = str(art.get("relative_path", ""))
            exp_h = str(art.get("sha256", ""))
            exp_sz = int(art["size_bytes"]) if art.get("size_bytes") is not None else None
            if rel:
                expected_entries.append((rel, exp_h, exp_sz))
    elif "hashes" in mdata and isinstance(mdata["hashes"], dict):
        for rel, exp_h in mdata["hashes"].items():
            expected_entries.append((str(rel), str(exp_h), None))

    if not expected_entries:
        return VerificationReport(
            case_id=case_id,
            verified_utc=verified_utc,
            manifest_relpath=manifest_filename,
            manifest_sha256=manifest_sha,
            overall_status=VerificationStatus.MANIFEST_INVALID.value,
            schema_version=schema_ver,
            checked_count=0,
            verified_count=0,
            mismatch_count=0,
            missing_count=0,
            items=[],
            notes=["Manifest contains no artifact hash entries."],
        )

    items: List[VerificationItemResult] = []
    verified_cnt = 0
    mismatch_cnt = 0
    missing_cnt = 0

    for rel, exp_h, exp_sz in expected_entries:
        # Reject circular self-hash if someone malformed a manifest
        if rel == manifest_filename:
            mismatch_cnt += 1
            items.append(
                VerificationItemResult(
                    relative_path=rel,
                    expected_sha256=exp_h,
                    actual_sha256=manifest_sha,
                    expected_size=exp_sz,
                    actual_size=None,
                    status=VerificationStatus.MISMATCH.value,
                )
            )
            continue

        apath = cpath / rel
        if not apath.exists() or not apath.is_file():
            missing_cnt += 1
            items.append(
                VerificationItemResult(
                    relative_path=rel,
                    expected_sha256=exp_h,
                    actual_sha256=None,
                    expected_size=exp_sz,
                    actual_size=None,
                    status=VerificationStatus.MISSING_ARTIFACT.value,
                )
            )
            continue

        act_sz, act_h = compute_file_sha256(apath)
        size_ok = (exp_sz is None) or (act_sz == exp_sz)
        hash_ok = act_h.lower() == exp_h.lower()
        if size_ok and hash_ok:
            st = VerificationStatus.VERIFIED.value
            verified_cnt += 1
        else:
            st = VerificationStatus.MISMATCH.value
            mismatch_cnt += 1

        items.append(
            VerificationItemResult(
                relative_path=rel,
                expected_sha256=exp_h,
                actual_sha256=act_h,
                expected_size=exp_sz,
                actual_size=act_sz,
                status=st,
            )
        )

    if missing_cnt > 0 and mismatch_cnt == 0:
        overall = VerificationStatus.MISSING_ARTIFACT.value
    elif mismatch_cnt > 0:
        overall = VerificationStatus.MISMATCH.value
    else:
        overall = VerificationStatus.VERIFIED.value

    return VerificationReport(
        case_id=case_id,
        verified_utc=verified_utc,
        manifest_relpath=manifest_filename,
        manifest_sha256=manifest_sha,
        overall_status=overall,
        schema_version=schema_ver,
        checked_count=len(items),
        verified_count=verified_cnt,
        mismatch_count=mismatch_cnt,
        missing_count=missing_cnt,
        items=items,
    )
