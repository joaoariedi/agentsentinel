"""
Infrastructure Monitor - Unified monitoring using OSquery and Wazuh.

Aggregates security events from both sources, establishes baselines,
detects anomalies, and triggers alerts for agent security violations.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Optional

from .osquery_client import OSQueryClient
from .wazuh_client import WazuhClient, WazuhAlert, WazuhClientError

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def from_wazuh_level(cls, level: int) -> AlertSeverity:
        """Map Wazuh rule level to AlertSeverity."""
        if level >= 12:
            return cls.CRITICAL
        elif level >= 10:
            return cls.HIGH
        elif level >= 7:
            return cls.MEDIUM
        elif level >= 4:
            return cls.LOW
        return cls.INFO


@dataclass
class InfraAlert:
    """Infrastructure security alert."""
    
    source: str  # "osquery", "wazuh", or "monitor"
    severity: AlertSeverity
    title: str
    description: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: Optional[str] = None
    process_name: Optional[str] = None
    data: dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_critical(self) -> bool:
        """Check if alert requires immediate attention."""
        return self.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "source": self.source,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "process_name": self.process_name,
            "data": self.data,
        }


# Type alias for alert handler callbacks
AlertHandler = Callable[[InfraAlert], Awaitable[None]]


class InfrastructureMonitor:
    """
    Unified infrastructure monitoring using OSquery and Wazuh.
    
    Features:
    - File integrity monitoring
    - Network connection tracking
    - Process monitoring
    - Alert aggregation from multiple sources
    - Baseline establishment and anomaly detection
    """
    
    # Suspicious ports commonly used by malware/C2
    SUSPICIOUS_PORTS = frozenset({
        4444,   # Metasploit default
        5555,   # Android ADB, common backdoor
        6666,   # IRC backdoor
        1337,   # "leet" port
        31337,  # Back Orifice
        8888,   # Common alt HTTP
        9999,   # Common backdoor
        12345,  # NetBus
        54321,  # Back Orifice 2000
    })
    
    # Suspicious process names
    SUSPICIOUS_PROCESSES = frozenset({
        "nc", "ncat", "netcat", "socat",  # Network utilities
        "msfconsole", "msfvenom",          # Metasploit
        "mimikatz", "lazagne",             # Credential dumping
        "tcpdump", "wireshark",            # Network sniffing
    })
    
    def __init__(
        self,
        osquery_socket: str = "/var/osquery/osquery.em",
        wazuh_host: str = "localhost",
        wazuh_port: int = 55000,
        wazuh_username: str = "wazuh",
        wazuh_password: str = "wazuh",
        wazuh_verify_ssl: bool = False,
    ):
        """
        Initialize infrastructure monitor.
        
        Args:
            osquery_socket: Path to OSquery extension socket
            wazuh_host: Wazuh Manager hostname
            wazuh_port: Wazuh API port
            wazuh_username: Wazuh API username
            wazuh_password: Wazuh API password
            wazuh_verify_ssl: Whether to verify Wazuh SSL certs
        """
        self.osquery = OSQueryClient(osquery_socket)
        
        try:
            self.wazuh = WazuhClient(
                host=wazuh_host,
                port=wazuh_port,
                username=wazuh_username,
                password=wazuh_password,
                verify_ssl=wazuh_verify_ssl,
            )
            self._wazuh_available = True
        except ImportError:
            self.wazuh = None  # type: ignore
            self._wazuh_available = False
            logger.warning("Wazuh client unavailable (httpx not installed)")
        
        # Alert handlers
        self._alert_handlers: list[AlertHandler] = []
        
        # Baseline data
        self._file_baselines: dict[str, dict[str, Any]] = {}
        self._network_baseline: set[str] = set()
        self._process_baseline: set[str] = set()
        
        # Monitoring state
        self._monitoring = False
        self._monitoring_task: Optional[asyncio.Task] = None
        
        # Seen alerts (for deduplication)
        self._seen_alert_ids: set[str] = set()
    
    def add_alert_handler(self, handler: AlertHandler) -> None:
        """
        Register an async handler for infrastructure alerts.
        
        Args:
            handler: Async function that receives InfraAlert
        """
        self._alert_handlers.append(handler)
    
    def remove_alert_handler(self, handler: AlertHandler) -> None:
        """Remove a previously registered alert handler."""
        if handler in self._alert_handlers:
            self._alert_handlers.remove(handler)
    
    async def _emit_alert(self, alert: InfraAlert) -> None:
        """Send alert to all registered handlers."""
        for handler in self._alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                logger.error(f"Alert handler error: {e}")
    
    def establish_baseline(
        self,
        config_files: list[str],
        include_network: bool = True,
        include_processes: bool = True,
    ) -> dict[str, Any]:
        """
        Establish baseline for file integrity and network connections.
        
        Args:
            config_files: List of file paths to monitor
            include_network: Whether to baseline network connections
            include_processes: Whether to baseline agent processes
            
        Returns:
            Dict with baseline summary
        """
        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files": 0,
            "connections": 0,
            "processes": 0,
        }
        
        # File integrity baseline
        if config_files:
            self._file_baselines = self.osquery.check_file_integrity(config_files)
            summary["files"] = len(self._file_baselines)
            logger.info(f"Baselined {summary['files']} files")
        
        # Network connection baseline
        if include_network:
            connections = self.osquery.get_network_connections()
            self._network_baseline = {
                f"{conn['remote_address']}:{conn['remote_port']}"
                for conn in connections
            }
            summary["connections"] = len(self._network_baseline)
            logger.info(f"Baselined {summary['connections']} network connections")
        
        # Process baseline
        if include_processes:
            processes = self.osquery.get_agent_processes()
            self._process_baseline = {
                f"{proc['name']}:{proc.get('path', '')}"
                for proc in processes
            }
            summary["processes"] = len(self._process_baseline)
            logger.info(f"Baselined {summary['processes']} agent processes")
        
        return summary
    
    async def check_file_integrity(
        self,
        paths: Optional[list[str]] = None,
    ) -> list[InfraAlert]:
        """
        Check if monitored files have been modified since baseline.
        
        Args:
            paths: Specific paths to check (or all baselined files)
            
        Returns:
            List of alerts for modified files
        """
        alerts = []
        check_paths = paths or list(self._file_baselines.keys())
        
        if not check_paths:
            return alerts
        
        current = self.osquery.check_file_integrity(check_paths)
        
        for path, info in current.items():
            baseline = self._file_baselines.get(path)
            
            if baseline:
                if info["sha256"] != baseline.get("sha256"):
                    alert = InfraAlert(
                        source="osquery",
                        severity=AlertSeverity.CRITICAL,
                        title="Configuration file modified",
                        description=f"File {path} hash changed",
                        data={
                            "path": path,
                            "old_hash": baseline.get("sha256", ""),
                            "new_hash": info["sha256"],
                            "old_mtime": baseline.get("mtime", ""),
                            "new_mtime": info["mtime"],
                        },
                    )
                    alerts.append(alert)
                    await self._emit_alert(alert)
            else:
                # New file not in baseline
                logger.debug(f"File {path} not in baseline, adding")
                self._file_baselines[path] = info
        
        # Check for deleted files
        for path in set(self._file_baselines.keys()) - set(current.keys()):
            alert = InfraAlert(
                source="osquery",
                severity=AlertSeverity.HIGH,
                title="Monitored file deleted",
                description=f"File {path} no longer exists",
                data={"path": path},
            )
            alerts.append(alert)
            await self._emit_alert(alert)
        
        return alerts
    
    async def check_network_anomalies(self) -> list[InfraAlert]:
        """
        Detect new or suspicious network connections.
        
        Returns:
            List of alerts for suspicious connections
        """
        alerts = []
        connections = self.osquery.get_network_connections()
        
        for conn in connections:
            remote = f"{conn['remote_address']}:{conn['remote_port']}"
            port = int(conn.get("remote_port", 0))
            process = conn.get("name", "unknown")
            
            # Check for new connections
            is_new = remote not in self._network_baseline
            is_suspicious_port = port in self.SUSPICIOUS_PORTS
            
            if is_new or is_suspicious_port:
                severity = AlertSeverity.MEDIUM
                title = "New outbound connection detected"
                
                if is_suspicious_port:
                    severity = AlertSeverity.HIGH
                    title = f"Connection to suspicious port {port}"
                
                alert = InfraAlert(
                    source="osquery",
                    severity=severity,
                    title=title,
                    description=f"Process {process} connected to {remote}",
                    process_name=process,
                    data={
                        "remote_address": conn.get("remote_address"),
                        "remote_port": port,
                        "local_port": conn.get("local_port"),
                        "process": process,
                        "pid": conn.get("pid"),
                        "state": conn.get("state"),
                        "is_new": is_new,
                        "is_suspicious_port": is_suspicious_port,
                    },
                )
                alerts.append(alert)
                await self._emit_alert(alert)
        
        return alerts
    
    async def check_processes(self) -> list[InfraAlert]:
        """
        Check for suspicious processes.
        
        Returns:
            List of alerts for suspicious processes
        """
        alerts = []
        processes = self.osquery.get_agent_processes()
        
        for proc in processes:
            name = proc.get("name", "").lower()
            cmdline = proc.get("cmdline", "").lower()
            
            # Check for suspicious process names
            if name in self.SUSPICIOUS_PROCESSES:
                alert = InfraAlert(
                    source="osquery",
                    severity=AlertSeverity.HIGH,
                    title=f"Suspicious process detected: {name}",
                    description=f"Process {name} (PID: {proc.get('pid')}) is running",
                    process_name=name,
                    data=proc,
                )
                alerts.append(alert)
                await self._emit_alert(alert)
            
            # Check for suspicious command patterns
            suspicious_patterns = [
                "curl" in cmdline and "|" in cmdline and ("sh" in cmdline or "bash" in cmdline),
                "wget" in cmdline and "|" in cmdline,
                "base64" in cmdline and "-d" in cmdline,
                "eval" in cmdline and "$(" in cmdline,
            ]
            
            if any(suspicious_patterns):
                alert = InfraAlert(
                    source="osquery",
                    severity=AlertSeverity.CRITICAL,
                    title="Suspicious command pattern detected",
                    description=f"Process running suspicious command",
                    process_name=name,
                    data={
                        "pid": proc.get("pid"),
                        "name": name,
                        "cmdline": proc.get("cmdline"),
                        "cwd": proc.get("cwd"),
                    },
                )
                alerts.append(alert)
                await self._emit_alert(alert)
        
        return alerts
    
    async def check_wazuh_alerts(
        self,
        rule_group: str = "agentsentinel",
        min_level: int = 6,
    ) -> list[InfraAlert]:
        """
        Fetch and process recent Wazuh alerts.
        
        Args:
            rule_group: Rule group to filter
            min_level: Minimum rule level
            
        Returns:
            List of InfraAlert from Wazuh
        """
        alerts = []
        
        if not self._wazuh_available or self.wazuh is None:
            return alerts
        
        try:
            wazuh_alerts = await self.wazuh.get_alerts(
                rule_group=rule_group,
                min_level=min_level,
            )
            
            for wa in wazuh_alerts:
                # Deduplicate
                if wa.id in self._seen_alert_ids:
                    continue
                self._seen_alert_ids.add(wa.id)
                
                # Keep seen_alerts bounded
                if len(self._seen_alert_ids) > 10000:
                    self._seen_alert_ids = set(
                        list(self._seen_alert_ids)[-5000:]
                    )
                
                severity = AlertSeverity.from_wazuh_level(wa.rule_level)
                
                alert = InfraAlert(
                    source="wazuh",
                    severity=severity,
                    title=wa.rule_description,
                    description=f"Wazuh rule {wa.rule_id} triggered (level {wa.rule_level})",
                    timestamp=wa.timestamp,
                    agent_id=wa.agent_id,
                    data={
                        "rule_id": wa.rule_id,
                        "rule_level": wa.rule_level,
                        "agent_name": wa.agent_name,
                        "groups": wa.groups,
                        **wa.data,
                    },
                )
                alerts.append(alert)
                await self._emit_alert(alert)
        
        except WazuhClientError as e:
            logger.warning(f"Error fetching Wazuh alerts: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching Wazuh alerts: {e}")
        
        return alerts
    
    async def run_security_scan(self) -> dict[str, Any]:
        """
        Run a comprehensive security scan.
        
        Returns:
            Dict with scan results and summary
        """
        results: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {},
            "alerts": [],
            "summary": {},
        }
        
        all_alerts: list[InfraAlert] = []
        
        # Check agent processes
        processes = self.osquery.get_agent_processes()
        results["checks"]["agent_processes"] = {
            "count": len(processes),
            "processes": processes[:10],  # Limit for response size
        }
        
        # Check file integrity
        file_alerts = await self.check_file_integrity()
        all_alerts.extend(file_alerts)
        results["checks"]["file_integrity"] = {
            "files_monitored": len(self._file_baselines),
            "alerts": len(file_alerts),
        }
        
        # Check network
        network_alerts = await self.check_network_anomalies()
        all_alerts.extend(network_alerts)
        results["checks"]["network"] = {
            "baseline_connections": len(self._network_baseline),
            "alerts": len(network_alerts),
        }
        
        # Check processes
        process_alerts = await self.check_processes()
        all_alerts.extend(process_alerts)
        results["checks"]["processes"] = {
            "alerts": len(process_alerts),
        }
        
        # Check Wazuh
        wazuh_alerts = await self.check_wazuh_alerts()
        all_alerts.extend(wazuh_alerts)
        results["checks"]["wazuh"] = {
            "available": self._wazuh_available,
            "alerts": len(wazuh_alerts),
        }
        
        # Build results
        results["alerts"] = [a.to_dict() for a in all_alerts]
        
        critical_count = len([a for a in all_alerts if a.severity == AlertSeverity.CRITICAL])
        high_count = len([a for a in all_alerts if a.severity == AlertSeverity.HIGH])
        
        results["summary"] = {
            "total_alerts": len(all_alerts),
            "critical": critical_count,
            "high": high_count,
            "medium": len([a for a in all_alerts if a.severity == AlertSeverity.MEDIUM]),
            "low": len([a for a in all_alerts if a.severity == AlertSeverity.LOW]),
            "info": len([a for a in all_alerts if a.severity == AlertSeverity.INFO]),
            "status": "compromised" if critical_count > 0 else (
                "warning" if high_count > 0 else "healthy"
            ),
        }
        
        return results
    
    async def _monitoring_loop(self, interval_seconds: int) -> None:
        """Internal monitoring loop."""
        while self._monitoring:
            try:
                await self.run_security_scan()
            except Exception as e:
                logger.error(f"Security scan error: {e}")
            
            await asyncio.sleep(interval_seconds)
    
    async def start_continuous_monitoring(
        self,
        interval_seconds: int = 60,
    ) -> None:
        """
        Start continuous monitoring loop.
        
        Args:
            interval_seconds: Seconds between scans
        """
        if self._monitoring:
            logger.warning("Monitoring already running")
            return
        
        self._monitoring = True
        self._monitoring_task = asyncio.create_task(
            self._monitoring_loop(interval_seconds)
        )
        logger.info(f"Started continuous monitoring (interval: {interval_seconds}s)")
    
    def stop_monitoring(self) -> None:
        """Stop the monitoring loop."""
        self._monitoring = False
        if self._monitoring_task:
            self._monitoring_task.cancel()
            self._monitoring_task = None
        logger.info("Stopped continuous monitoring")
    
    async def get_status(self) -> dict[str, Any]:
        """
        Get current monitor status.
        
        Returns:
            Dict with status information
        """
        osquery_available = self.osquery.is_available()
        wazuh_available = False
        
        if self._wazuh_available and self.wazuh:
            wazuh_available = await self.wazuh.is_available()
        
        return {
            "monitoring_active": self._monitoring,
            "osquery_available": osquery_available,
            "wazuh_available": wazuh_available,
            "baseline": {
                "files": len(self._file_baselines),
                "network_connections": len(self._network_baseline),
                "processes": len(self._process_baseline),
            },
            "alert_handlers": len(self._alert_handlers),
            "seen_alerts": len(self._seen_alert_ids),
        }
