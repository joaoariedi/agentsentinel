"""
OSquery Client - Unix socket client for OSquery daemon.

Provides SQL-based endpoint visibility for monitoring agent processes,
network connections, file integrity, and system state.
"""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class OSQueryResult:
    """Result from an OSquery query."""
    
    query: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    status: str = "success"
    messages: list[str] = field(default_factory=list)
    
    @property
    def success(self) -> bool:
        return self.status == "success" or self.status == "0"
    
    @property
    def count(self) -> int:
        return len(self.rows)


class OSQueryClient:
    """Client for OSquery daemon socket or CLI."""
    
    # Default socket path for osqueryd extension manager
    DEFAULT_SOCKET = "/var/osquery/osquery.em"
    
    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET,
        use_cli_fallback: bool = True,
        timeout: float = 10.0,
    ):
        """
        Initialize OSquery client.
        
        Args:
            socket_path: Path to osquery extension socket
            use_cli_fallback: If True, fall back to osqueryi CLI if socket unavailable
            timeout: Socket timeout in seconds
        """
        self.socket_path = socket_path
        self.use_cli_fallback = use_cli_fallback
        self.timeout = timeout
        self._socket_available: Optional[bool] = None
    
    def _check_socket_available(self) -> bool:
        """Check if osquery socket is available."""
        if self._socket_available is not None:
            return self._socket_available
        
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(self.socket_path)
            sock.close()
            self._socket_available = True
        except (socket.error, FileNotFoundError):
            self._socket_available = False
        
        return self._socket_available
    
    def _query_via_socket(self, sql: str) -> OSQueryResult:
        """Execute query via Unix socket."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            
            request = json.dumps({"query": sql})
            sock.sendall(request.encode() + b"\n")
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                # Check for complete JSON
                try:
                    json.loads(response.decode())
                    break
                except json.JSONDecodeError:
                    continue
            
            sock.close()
            
            result = json.loads(response.decode())
            return OSQueryResult(
                query=sql,
                rows=result.get("response", []),
                status=str(result.get("status", "0")),
                messages=result.get("messages", []),
            )
        except socket.timeout:
            return OSQueryResult(
                query=sql,
                status="error",
                messages=["Socket timeout"],
            )
        except Exception as e:
            return OSQueryResult(
                query=sql,
                status="error",
                messages=[str(e)],
            )
    
    def _query_via_cli(self, sql: str) -> OSQueryResult:
        """Execute query via osqueryi CLI (fallback)."""
        try:
            result = subprocess.run(
                ["osqueryi", "--json", sql],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            
            if result.returncode != 0:
                return OSQueryResult(
                    query=sql,
                    status="error",
                    messages=[result.stderr or f"Exit code: {result.returncode}"],
                )
            
            rows = json.loads(result.stdout) if result.stdout.strip() else []
            return OSQueryResult(
                query=sql,
                rows=rows,
                status="success",
            )
        except subprocess.TimeoutExpired:
            return OSQueryResult(
                query=sql,
                status="error",
                messages=["CLI timeout"],
            )
        except FileNotFoundError:
            return OSQueryResult(
                query=sql,
                status="error",
                messages=["osqueryi not found - is OSquery installed?"],
            )
        except Exception as e:
            return OSQueryResult(
                query=sql,
                status="error",
                messages=[str(e)],
            )
    
    def query(self, sql: str) -> OSQueryResult:
        """
        Execute a SQL query against osquery.
        
        Args:
            sql: SQL query to execute
            
        Returns:
            OSQueryResult with rows and status
        """
        # Try socket first
        if self._check_socket_available():
            return self._query_via_socket(sql)
        
        # Fallback to CLI
        if self.use_cli_fallback:
            return self._query_via_cli(sql)
        
        return OSQueryResult(
            query=sql,
            status="error",
            messages=["OSquery socket not available and CLI fallback disabled"],
        )
    
    def get_agent_processes(self) -> list[dict[str, Any]]:
        """
        Get all processes related to AI agents.
        
        Returns:
            List of process information dicts
        """
        result = self.query("""
            SELECT p.pid, p.name, p.path, p.cmdline, p.cwd, 
                   p.uid, u.username, p.start_time, p.resident_size
            FROM processes p 
            LEFT JOIN users u ON p.uid = u.uid 
            WHERE p.name LIKE '%python%' 
               OR p.name LIKE '%node%' 
               OR p.cmdline LIKE '%agent%'
               OR p.cmdline LIKE '%clawdbot%'
               OR p.cmdline LIKE '%sentinel%'
        """)
        return result.rows
    
    def get_network_connections(self, pid: Optional[int] = None) -> list[dict[str, Any]]:
        """
        Get network connections, optionally filtered by PID.
        
        Args:
            pid: Optional process ID to filter by
            
        Returns:
            List of network connection dicts
        """
        where_clause = f"AND s.pid = {pid}" if pid else ""
        result = self.query(f"""
            SELECT s.pid, p.name, s.remote_address, s.remote_port, 
                   s.local_address, s.local_port, s.state, s.protocol
            FROM process_open_sockets s 
            JOIN processes p ON s.pid = p.pid 
            WHERE s.remote_address NOT IN ('127.0.0.1', '::1', '0.0.0.0', '')
            {where_clause}
        """)
        return result.rows
    
    def get_file_events(self, path_pattern: str, limit: int = 100) -> list[dict[str, Any]]:
        """
        Get file access events matching a pattern.
        
        Note: Requires file_events table (FIM must be enabled).
        
        Args:
            path_pattern: SQL LIKE pattern for file paths
            limit: Maximum number of events to return
            
        Returns:
            List of file event dicts
        """
        # Escape single quotes in pattern
        safe_pattern = path_pattern.replace("'", "''")
        result = self.query(f"""
            SELECT target_path, action, time, uid
            FROM file_events 
            WHERE target_path LIKE '{safe_pattern}'
            ORDER BY time DESC
            LIMIT {limit}
        """)
        return result.rows
    
    def check_file_integrity(self, paths: list[str]) -> dict[str, dict[str, Any]]:
        """
        Check SHA256 hashes and metadata of specified files.
        
        Args:
            paths: List of file paths to check
            
        Returns:
            Dict mapping path to {sha256, mtime, size}
        """
        if not paths:
            return {}
        
        path_list = ",".join(f"'{p.replace(chr(39), chr(39)+chr(39))}'" for p in paths)
        result = self.query(f"""
            SELECT f.path, h.sha256, f.mtime, f.size
            FROM file f
            JOIN hash h ON f.path = h.path
            WHERE f.path IN ({path_list})
        """)
        
        return {
            row["path"]: {
                "sha256": row.get("sha256", ""),
                "mtime": row.get("mtime", ""),
                "size": row.get("size", 0),
            }
            for row in result.rows
        }
    
    def get_listening_ports(self) -> list[dict[str, Any]]:
        """
        Get all listening ports and their associated processes.
        
        Returns:
            List of listening port dicts
        """
        result = self.query("""
            SELECT l.pid, p.name, l.port, l.protocol, l.address
            FROM listening_ports l 
            JOIN processes p ON l.pid = p.pid
            ORDER BY l.port
        """)
        return result.rows
    
    def get_docker_containers(self) -> list[dict[str, Any]]:
        """
        Get running Docker containers.
        
        Returns:
            List of container dicts
        """
        result = self.query("""
            SELECT id, name, image, state, started_at, 
                   ip_address, pid
            FROM docker_containers
        """)
        return result.rows
    
    def get_cron_jobs(self) -> list[dict[str, Any]]:
        """
        Get all scheduled cron jobs.
        
        Returns:
            List of cron job dicts
        """
        result = self.query("SELECT * FROM crontab")
        return result.rows
    
    def get_shell_history(
        self,
        suspicious_only: bool = True,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Get shell command history.
        
        Args:
            suspicious_only: If True, filter for suspicious commands
            limit: Maximum number of entries
            
        Returns:
            List of shell history dicts
        """
        if suspicious_only:
            result = self.query(f"""
                SELECT uid, username, command, time
                FROM shell_history 
                WHERE command LIKE '%curl%' 
                   OR command LIKE '%wget%' 
                   OR command LIKE '%nc %'
                   OR command LIKE '%netcat%'
                   OR command LIKE '%base64%'
                   OR command LIKE '%eval%'
                   OR command LIKE '%exec%'
                ORDER BY time DESC
                LIMIT {limit}
            """)
        else:
            result = self.query(f"""
                SELECT uid, username, command, time
                FROM shell_history 
                ORDER BY time DESC
                LIMIT {limit}
            """)
        return result.rows
    
    def get_system_info(self) -> dict[str, Any]:
        """
        Get basic system information.
        
        Returns:
            Dict with system info
        """
        result = self.query("""
            SELECT hostname, uuid, cpu_type, cpu_brand, 
                   physical_memory, hardware_vendor
            FROM system_info
        """)
        return result.rows[0] if result.rows else {}
    
    def is_available(self) -> bool:
        """
        Check if OSquery is available (socket or CLI).
        
        Returns:
            True if OSquery can be queried
        """
        if self._check_socket_available():
            return True
        
        if self.use_cli_fallback:
            result = self._query_via_cli("SELECT 1 AS test")
            return result.success
        
        return False
