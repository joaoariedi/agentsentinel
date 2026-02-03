"""
Unit tests for Infrastructure Monitor module.

Tests OSquery client, Wazuh client, and InfrastructureMonitor
with mock data (no actual services required).
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from agentsentinel.infra_monitor import (
    OSQueryClient,
    OSQueryResult,
    WazuhClient,
    WazuhAlert,
    InfrastructureMonitor,
    InfraAlert,
    AlertSeverity,
)
from agentsentinel.infra_monitor.wazuh_client import WazuhAgentInfo, WazuhClientError


class TestOSQueryResult:
    """Tests for OSQueryResult dataclass."""
    
    def test_success_status(self):
        result = OSQueryResult(query="SELECT 1", rows=[{"1": "1"}], status="0")
        assert result.success is True
        assert result.count == 1
    
    def test_error_status(self):
        result = OSQueryResult(query="SELECT 1", status="error", messages=["fail"])
        assert result.success is False
        assert result.count == 0


class TestOSQueryClient:
    """Tests for OSQueryClient."""
    
    def test_init_defaults(self):
        client = OSQueryClient()
        assert client.socket_path == "/var/osquery/osquery.em"
        assert client.use_cli_fallback is True
        assert client.timeout == 10.0
    
    def test_init_custom(self):
        client = OSQueryClient(
            socket_path="/custom/socket",
            use_cli_fallback=False,
            timeout=5.0,
        )
        assert client.socket_path == "/custom/socket"
        assert client.use_cli_fallback is False
        assert client.timeout == 5.0
    
    @patch("subprocess.run")
    def test_query_via_cli(self, mock_run):
        """Test CLI fallback query execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[{"pid": "1234", "name": "python"}]',
            stderr="",
        )
        
        client = OSQueryClient(use_cli_fallback=True)
        client._socket_available = False  # Force CLI fallback
        
        result = client.query("SELECT * FROM processes")
        
        assert result.success
        assert len(result.rows) == 1
        assert result.rows[0]["pid"] == "1234"
    
    @patch("subprocess.run")
    def test_query_cli_error(self, mock_run):
        """Test CLI error handling."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error: bad query",
        )
        
        client = OSQueryClient(use_cli_fallback=True)
        client._socket_available = False
        
        result = client.query("SELECT * FROM nonexistent")
        
        assert not result.success
        assert "bad query" in result.messages[0] or "Exit code" in result.messages[0]
    
    @patch("subprocess.run")
    def test_get_agent_processes(self, mock_run):
        """Test get_agent_processes method."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[{"pid": "100", "name": "python", "cmdline": "python agent.py"}]',
            stderr="",
        )
        
        client = OSQueryClient()
        client._socket_available = False
        
        processes = client.get_agent_processes()
        
        assert len(processes) == 1
        assert processes[0]["name"] == "python"
    
    @patch("subprocess.run")
    def test_check_file_integrity(self, mock_run):
        """Test file integrity checking."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[{"path": "/app/.env", "sha256": "abc123", "mtime": "1234567890", "size": "100"}]',
            stderr="",
        )
        
        client = OSQueryClient()
        client._socket_available = False
        
        result = client.check_file_integrity(["/app/.env"])
        
        assert "/app/.env" in result
        assert result["/app/.env"]["sha256"] == "abc123"
    
    @patch("subprocess.run")
    def test_get_network_connections(self, mock_run):
        """Test network connection retrieval."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[{"pid": "100", "name": "python", "remote_address": "8.8.8.8", "remote_port": "443"}]',
            stderr="",
        )
        
        client = OSQueryClient()
        client._socket_available = False
        
        connections = client.get_network_connections()
        
        assert len(connections) == 1
        assert connections[0]["remote_address"] == "8.8.8.8"


class TestWazuhAlert:
    """Tests for WazuhAlert dataclass."""
    
    def test_from_api_response(self):
        """Test creating WazuhAlert from API response."""
        api_item = {
            "id": "alert-123",
            "timestamp": "2024-01-15T10:30:00Z",
            "rule": {
                "id": "100001",
                "level": 12,
                "description": "Test alert",
                "groups": ["agentsentinel", "critical"],
            },
            "agent": {
                "id": "001",
                "name": "test-agent",
            },
            "data": {"extra": "info"},
        }
        
        alert = WazuhAlert.from_api_response(api_item)
        
        assert alert.id == "alert-123"
        assert alert.rule_id == 100001
        assert alert.rule_level == 12
        assert alert.rule_description == "Test alert"
        assert alert.agent_id == "001"
        assert alert.is_critical is True
        assert alert.is_agentsentinel is True
    
    def test_is_high(self):
        """Test is_high property."""
        alert = WazuhAlert(
            id="1",
            timestamp=datetime.now(timezone.utc),
            rule_id=100010,
            rule_level=10,
            rule_description="High alert",
            agent_id="001",
            agent_name="test",
        )
        assert alert.is_high is True
        assert alert.is_critical is False


class TestWazuhAgentInfo:
    """Tests for WazuhAgentInfo dataclass."""
    
    def test_from_api_response(self):
        """Test creating WazuhAgentInfo from API response."""
        api_item = {
            "id": "001",
            "name": "test-agent",
            "ip": "192.168.1.100",
            "status": "active",
            "os": {"name": "Ubuntu", "version": "22.04"},
            "version": "4.7.0",
            "lastKeepAlive": "2024-01-15T10:30:00Z",
        }
        
        info = WazuhAgentInfo.from_api_response(api_item)
        
        assert info.id == "001"
        assert info.name == "test-agent"
        assert info.is_active is True
        assert info.os_name == "Ubuntu"


class TestWazuhClient:
    """Tests for WazuhClient."""
    
    def test_init(self):
        """Test client initialization."""
        client = WazuhClient(
            host="wazuh.local",
            port=55000,
            username="admin",
            password="secret",
        )
        
        assert client.base_url == "https://wazuh.local:55000"
        assert client.username == "admin"
    
    @pytest.mark.asyncio
    async def test_authenticate(self):
        """Test authentication."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "data": {"token": "test-jwt-token"}
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            
            client = WazuhClient()
            token = await client.authenticate()
            
            assert token == "test-jwt-token"
            assert client._token == "test-jwt-token"
    
    @pytest.mark.asyncio
    async def test_get_alerts(self):
        """Test fetching alerts."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            # Mock auth response
            auth_response = MagicMock()
            auth_response.json.return_value = {"data": {"token": "token"}}
            auth_response.raise_for_status = MagicMock()
            
            # Mock alerts response
            alerts_response = MagicMock()
            alerts_response.json.return_value = {
                "data": {
                    "affected_items": [
                        {
                            "id": "1",
                            "timestamp": "2024-01-15T10:30:00Z",
                            "rule": {"id": 100001, "level": 12, "description": "Test", "groups": []},
                            "agent": {"id": "001", "name": "test"},
                            "data": {},
                        }
                    ]
                }
            }
            alerts_response.raise_for_status = MagicMock()
            
            mock_client.post.return_value = auth_response
            mock_client.request.return_value = alerts_response
            
            client = WazuhClient()
            alerts = await client.get_alerts()
            
            assert len(alerts) == 1
            assert alerts[0].rule_id == 100001


class TestAlertSeverity:
    """Tests for AlertSeverity enum."""
    
    def test_from_wazuh_level(self):
        """Test mapping Wazuh levels to severity."""
        assert AlertSeverity.from_wazuh_level(15) == AlertSeverity.CRITICAL
        assert AlertSeverity.from_wazuh_level(12) == AlertSeverity.CRITICAL
        assert AlertSeverity.from_wazuh_level(10) == AlertSeverity.HIGH
        assert AlertSeverity.from_wazuh_level(7) == AlertSeverity.MEDIUM
        assert AlertSeverity.from_wazuh_level(4) == AlertSeverity.LOW
        assert AlertSeverity.from_wazuh_level(2) == AlertSeverity.INFO


class TestInfraAlert:
    """Tests for InfraAlert dataclass."""
    
    def test_is_critical(self):
        """Test is_critical property."""
        critical = InfraAlert(
            source="test",
            severity=AlertSeverity.CRITICAL,
            title="Critical Alert",
            description="Test",
        )
        assert critical.is_critical is True
        
        high = InfraAlert(
            source="test",
            severity=AlertSeverity.HIGH,
            title="High Alert",
            description="Test",
        )
        assert high.is_critical is True
        
        medium = InfraAlert(
            source="test",
            severity=AlertSeverity.MEDIUM,
            title="Medium Alert",
            description="Test",
        )
        assert medium.is_critical is False
    
    def test_to_dict(self):
        """Test serialization."""
        alert = InfraAlert(
            source="osquery",
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            description="Test description",
            agent_id="agent-1",
            data={"key": "value"},
        )
        
        d = alert.to_dict()
        
        assert d["source"] == "osquery"
        assert d["severity"] == "high"
        assert d["title"] == "Test Alert"
        assert d["data"]["key"] == "value"


class TestInfrastructureMonitor:
    """Tests for InfrastructureMonitor."""
    
    def test_init(self):
        """Test monitor initialization."""
        monitor = InfrastructureMonitor()
        
        assert monitor.osquery is not None
        assert len(monitor._alert_handlers) == 0
        assert monitor._monitoring is False
    
    def test_add_alert_handler(self):
        """Test adding alert handlers."""
        monitor = InfrastructureMonitor()
        
        async def handler(alert):
            pass
        
        monitor.add_alert_handler(handler)
        assert len(monitor._alert_handlers) == 1
        
        monitor.remove_alert_handler(handler)
        assert len(monitor._alert_handlers) == 0
    
    @patch.object(OSQueryClient, "check_file_integrity")
    def test_establish_baseline(self, mock_check):
        """Test baseline establishment."""
        mock_check.return_value = {
            "/app/.env": {"sha256": "abc123", "mtime": "123", "size": 100}
        }
        
        monitor = InfrastructureMonitor()
        
        # Mock other methods
        with patch.object(monitor.osquery, "get_network_connections", return_value=[]):
            with patch.object(monitor.osquery, "get_agent_processes", return_value=[]):
                summary = monitor.establish_baseline(["/app/.env"])
        
        assert summary["files"] == 1
        assert "/app/.env" in monitor._file_baselines
    
    @pytest.mark.asyncio
    async def test_check_file_integrity_changed(self):
        """Test file integrity check detecting changes."""
        monitor = InfrastructureMonitor()
        
        # Set baseline
        monitor._file_baselines = {
            "/app/.env": {"sha256": "old_hash", "mtime": "100", "size": 50}
        }
        
        # Mock current state with different hash
        with patch.object(
            monitor.osquery,
            "check_file_integrity",
            return_value={
                "/app/.env": {"sha256": "new_hash", "mtime": "200", "size": 60}
            },
        ):
            alerts = await monitor.check_file_integrity()
        
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.CRITICAL
        assert "modified" in alerts[0].title.lower()
    
    @pytest.mark.asyncio
    async def test_check_network_anomalies(self):
        """Test network anomaly detection."""
        monitor = InfrastructureMonitor()
        
        # Set baseline
        monitor._network_baseline = {"1.1.1.1:443"}
        
        # Mock new connection to suspicious port
        with patch.object(
            monitor.osquery,
            "get_network_connections",
            return_value=[
                {
                    "pid": "100",
                    "name": "python",
                    "remote_address": "evil.com",
                    "remote_port": "4444",  # Suspicious port
                    "local_port": "12345",
                    "state": "ESTABLISHED",
                }
            ],
        ):
            alerts = await monitor.check_network_anomalies()
        
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.HIGH
        assert "suspicious port" in alerts[0].title.lower()
    
    @pytest.mark.asyncio
    async def test_check_processes_suspicious(self):
        """Test suspicious process detection."""
        monitor = InfrastructureMonitor()
        
        # Mock suspicious process
        with patch.object(
            monitor.osquery,
            "get_agent_processes",
            return_value=[
                {
                    "pid": "999",
                    "name": "netcat",
                    "cmdline": "nc -lvp 4444",
                    "cwd": "/tmp",
                }
            ],
        ):
            alerts = await monitor.check_processes()
        
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.HIGH
        assert "netcat" in alerts[0].title.lower()
    
    @pytest.mark.asyncio
    async def test_run_security_scan(self):
        """Test comprehensive security scan."""
        monitor = InfrastructureMonitor()
        monitor._wazuh_available = False  # Disable Wazuh for this test
        
        # Mock all checks
        with patch.object(monitor.osquery, "get_agent_processes", return_value=[]):
            with patch.object(monitor.osquery, "check_file_integrity", return_value={}):
                with patch.object(monitor.osquery, "get_network_connections", return_value=[]):
                    results = await monitor.run_security_scan()
        
        assert "timestamp" in results
        assert "checks" in results
        assert "summary" in results
        assert results["summary"]["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_alert_handler_called(self):
        """Test that alert handlers are called."""
        monitor = InfrastructureMonitor()
        
        received_alerts = []
        
        async def handler(alert):
            received_alerts.append(alert)
        
        monitor.add_alert_handler(handler)
        
        # Set baseline
        monitor._file_baselines = {"/test": {"sha256": "old", "mtime": "1", "size": 1}}
        
        # Mock changed file
        with patch.object(
            monitor.osquery,
            "check_file_integrity",
            return_value={"/test": {"sha256": "new", "mtime": "2", "size": 2}},
        ):
            await monitor.check_file_integrity()
        
        assert len(received_alerts) == 1
        assert received_alerts[0].source == "osquery"
    
    @pytest.mark.asyncio
    async def test_get_status(self):
        """Test status reporting."""
        monitor = InfrastructureMonitor()
        monitor._wazuh_available = False
        
        with patch.object(monitor.osquery, "is_available", return_value=True):
            status = await monitor.get_status()
        
        assert "monitoring_active" in status
        assert "osquery_available" in status
        assert status["osquery_available"] is True
    
    def test_stop_monitoring(self):
        """Test stopping monitoring."""
        monitor = InfrastructureMonitor()
        monitor._monitoring = True
        
        monitor.stop_monitoring()
        
        assert monitor._monitoring is False


class TestIntegration:
    """Integration-style tests (still mocked but test workflows)."""
    
    @pytest.mark.asyncio
    async def test_full_monitoring_workflow(self):
        """Test complete monitoring workflow."""
        monitor = InfrastructureMonitor()
        monitor._wazuh_available = False
        
        # Track alerts
        alerts_received = []
        
        async def alert_handler(alert):
            alerts_received.append(alert)
        
        monitor.add_alert_handler(alert_handler)
        
        # Mock OSquery responses
        with patch.object(
            monitor.osquery,
            "check_file_integrity",
            side_effect=[
                {"/app/.env": {"sha256": "hash1", "mtime": "1", "size": 100}},  # Baseline
                {"/app/.env": {"sha256": "hash2", "mtime": "2", "size": 150}},  # Changed
            ],
        ):
            with patch.object(monitor.osquery, "get_network_connections", return_value=[]):
                with patch.object(monitor.osquery, "get_agent_processes", return_value=[]):
                    # Establish baseline
                    monitor.establish_baseline(["/app/.env"])
                    
                    # Run scan (should detect file change)
                    results = await monitor.run_security_scan()
        
        # Verify alerts were generated
        assert len(alerts_received) >= 1
        file_alerts = [a for a in alerts_received if "file" in a.title.lower()]
        assert len(file_alerts) == 1
        
        # Verify scan results
        assert results["summary"]["critical"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
