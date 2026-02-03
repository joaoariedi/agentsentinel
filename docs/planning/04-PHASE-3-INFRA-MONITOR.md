# Phase 3: Infrastructure Monitor - Wazuh & OSquery Integration

**Duration:** Days 4-6
**Goal:** Monitor the host infrastructure where agents run using enterprise-grade security tools

---

## Overview

Even if an agent's logic is secure, its host can be compromised. Infrastructure monitoring provides visibility into:

- File integrity (config tampering)
- Process execution (malicious processes)
- Network connections (C2, data exfiltration)
- System changes (privilege escalation)

### Stack

- **Wazuh** - SIEM, log analysis, intrusion detection, compliance
- **OSquery** - SQL-based endpoint visibility

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Host Machine                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Agent     │  │  OSquery    │  │    Wazuh Agent      │  │
│  │  Process    │  │  Daemon     │  │                     │  │
│  │             │  │             │  │  • File Integrity   │  │
│  │  python     │  │  osqueryd   │  │  • Log Collection   │  │
│  │  agent.py   │  │             │  │  • Rootkit Detect   │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │             │
└─────────┼────────────────┼─────────────────────┼─────────────┘
          │                │                     │
          │    ┌───────────┴───────────┐         │
          │    │   Local Socket/API    │         │
          │    └───────────┬───────────┘         │
          │                │                     │
          ▼                ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│              AgentSentinel Infra Monitor                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  Alert Aggregator                    │    │
│  │                                                      │    │
│  │  • Correlate OSquery + Wazuh alerts                 │    │
│  │  • Apply agent-specific rules                        │    │
│  │  • Trigger circuit breakers                          │    │
│  │  • Send to Solana registry                           │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Wazuh Manager                             │
│  • Centralized alert management                              │
│  • Dashboard & visualization                                 │
│  • Rule engine                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation

### 3.1 OSquery Configuration

```sql
-- configs/osquery/agentsentinel.conf
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem,syslog",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "schedule_splay_percent": "10",
    "pidfile": "/var/osquery/osquery.pidfile",
    "events_expiry": "3600",
    "database_path": "/var/osquery/osquery.db",
    "verbose": "false",
    "worker_threads": "2",
    "enable_monitor": "true"
  },
  
  "schedule": {
    "agent_processes": {
      "query": "SELECT p.pid, p.name, p.path, p.cmdline, p.cwd, p.uid, u.username, p.start_time FROM processes p LEFT JOIN users u ON p.uid = u.uid WHERE p.name LIKE '%python%' OR p.name LIKE '%node%' OR p.cmdline LIKE '%agent%'",
      "interval": 60,
      "description": "Monitor agent-related processes"
    },
    
    "sensitive_file_access": {
      "query": "SELECT * FROM file_events WHERE target_path LIKE '%/.env%' OR target_path LIKE '%/secrets%' OR target_path LIKE '%wallet%' OR target_path LIKE '%private%' OR target_path LIKE '%key.json%'",
      "interval": 30,
      "description": "Monitor access to sensitive files"
    },
    
    "env_file_integrity": {
      "query": "SELECT path, sha256, mtime FROM hash WHERE path IN ('/app/.env', '/home/agent/.env', '/etc/agentsentinel/config.yaml')",
      "interval": 300,
      "description": "Check integrity of configuration files"
    },
    
    "network_connections": {
      "query": "SELECT DISTINCT s.pid, p.name, s.remote_address, s.remote_port, s.local_port, s.state FROM process_open_sockets s JOIN processes p ON s.pid = p.pid WHERE s.remote_address NOT IN ('127.0.0.1', '::1', '0.0.0.0') AND s.remote_address != ''",
      "interval": 60,
      "description": "Monitor outbound network connections"
    },
    
    "listening_ports": {
      "query": "SELECT l.pid, p.name, l.port, l.protocol, l.address FROM listening_ports l JOIN processes p ON l.pid = p.pid",
      "interval": 300,
      "description": "Monitor listening ports"
    },
    
    "cron_jobs": {
      "query": "SELECT * FROM crontab",
      "interval": 3600,
      "description": "Monitor scheduled tasks"
    },
    
    "shell_history": {
      "query": "SELECT * FROM shell_history WHERE command LIKE '%curl%' OR command LIKE '%wget%' OR command LIKE '%nc %' OR command LIKE '%base64%'",
      "interval": 300,
      "description": "Monitor suspicious shell commands"
    },
    
    "sudo_usage": {
      "query": "SELECT * FROM last WHERE type = 7",
      "interval": 60,
      "description": "Monitor privilege escalation"
    },
    
    "docker_containers": {
      "query": "SELECT id, name, image, state, started_at FROM docker_containers",
      "interval": 120,
      "description": "Monitor Docker containers"
    },
    
    "memory_map_suspicious": {
      "query": "SELECT pid, path FROM process_memory_map WHERE path LIKE '/dev/shm%' OR path LIKE '/tmp%'",
      "interval": 300,
      "description": "Detect in-memory execution"
    }
  },
  
  "file_paths": {
    "agent_configs": [
      "/app/.env",
      "/app/config/%%",
      "/home/agent/.env"
    ],
    "wallet_files": [
      "/home/agent/.config/solana/%%",
      "/app/wallets/%%"
    ],
    "ssh_keys": [
      "/home/%%/.ssh/%%"
    ]
  },
  
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT hostname FROM system_info;"
    ]
  }
}
```

### 3.2 Wazuh Custom Rules

```xml
<!-- configs/wazuh/rules/agentsentinel_rules.xml -->
<group name="agentsentinel,">
  
  <!-- File Integrity Alerts -->
  <rule id="100001" level="12">
    <if_sid>550</if_sid>
    <match>\.env|secrets|wallet|private_key</match>
    <description>AgentSentinel: Sensitive configuration file modified</description>
    <group>agentsentinel,file_integrity,critical</group>
  </rule>
  
  <rule id="100002" level="15">
    <if_sid>550</if_sid>
    <match>wallet.*\.json|keypair.*\.json</match>
    <description>AgentSentinel: Wallet file modified - potential compromise</description>
    <group>agentsentinel,file_integrity,critical</group>
  </rule>
  
  <!-- Process Alerts -->
  <rule id="100010" level="10">
    <decoded_as>osquery</decoded_as>
    <field name="name">agent_processes</field>
    <description>AgentSentinel: Agent process activity detected</description>
    <group>agentsentinel,process,info</group>
  </rule>
  
  <rule id="100011" level="14">
    <decoded_as>osquery</decoded_as>
    <field name="cmdline">curl.*\|.*sh|wget.*\|.*bash|base64.*-d</field>
    <description>AgentSentinel: Suspicious command execution pattern</description>
    <group>agentsentinel,process,critical</group>
  </rule>
  
  <rule id="100012" level="12">
    <decoded_as>osquery</decoded_as>
    <field name="name">nc|ncat|netcat|socat</field>
    <description>AgentSentinel: Network utility executed by agent</description>
    <group>agentsentinel,process,high</group>
  </rule>
  
  <!-- Network Alerts -->
  <rule id="100020" level="8">
    <decoded_as>osquery</decoded_as>
    <field name="name">network_connections</field>
    <field name="remote_port">^(4444|5555|6666|1337|31337)$</field>
    <description>AgentSentinel: Connection to suspicious port</description>
    <group>agentsentinel,network,high</group>
  </rule>
  
  <rule id="100021" level="10">
    <decoded_as>osquery</decoded_as>
    <field name="name">network_connections</field>
    <match>tor|onion|i2p</match>
    <description>AgentSentinel: Connection to anonymization network</description>
    <group>agentsentinel,network,high</group>
  </rule>
  
  <rule id="100022" level="6">
    <decoded_as>osquery</decoded_as>
    <field name="name">network_connections</field>
    <description>AgentSentinel: New outbound connection from agent</description>
    <group>agentsentinel,network,info</group>
  </rule>
  
  <!-- Privilege Escalation -->
  <rule id="100030" level="12">
    <if_sid>5401</if_sid>
    <match>agent|python|node</match>
    <description>AgentSentinel: Agent process attempted sudo</description>
    <group>agentsentinel,privilege,high</group>
  </rule>
  
  <!-- Data Exfiltration Indicators -->
  <rule id="100040" level="14">
    <decoded_as>osquery</decoded_as>
    <field name="name">shell_history</field>
    <match>curl.*-d.*key|wget.*key|curl.*POST.*wallet</match>
    <description>AgentSentinel: Potential key exfiltration attempt</description>
    <group>agentsentinel,exfiltration,critical</group>
  </rule>
  
  <!-- Container Escape Attempts -->
  <rule id="100050" level="15">
    <decoded_as>osquery</decoded_as>
    <match>/proc/1/root|nsenter|--privileged</match>
    <description>AgentSentinel: Potential container escape attempt</description>
    <group>agentsentinel,container,critical</group>
  </rule>
  
</group>
```

### 3.3 Wazuh Decoder

```xml
<!-- configs/wazuh/decoders/agentsentinel_decoders.xml -->
<decoder name="agentsentinel-json">
  <prematch>^{"agent_id":</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>

<decoder name="agentsentinel-action">
  <parent>agentsentinel-json</parent>
  <regex>\"action_type\":\"(\w+)\"</regex>
  <order>action_type</order>
</decoder>

<decoder name="agentsentinel-anomaly">
  <parent>agentsentinel-json</parent>
  <regex>\"anomaly_score\":([\d.]+)</regex>
  <order>anomaly_score</order>
</decoder>
```

### 3.4 Python Integration Module

```python
# src/infra_monitor/osquery_client.py
import json
import socket
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

@dataclass
class OSQueryResult:
    query: str
    rows: List[Dict[str, Any]]
    status: str
    messages: List[str]

class OSQueryClient:
    """Client for OSquery daemon socket"""
    
    def __init__(self, socket_path: str = "/var/osquery/osquery.em"):
        self.socket_path = socket_path
    
    def query(self, sql: str) -> OSQueryResult:
        """Execute a SQL query against osquery"""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.socket_path)
            
            request = json.dumps({"query": sql})
            sock.sendall(request.encode() + b"\n")
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            sock.close()
            
            result = json.loads(response.decode())
            return OSQueryResult(
                query=sql,
                rows=result.get("response", []),
                status=result.get("status", "unknown"),
                messages=result.get("messages", [])
            )
        except Exception as e:
            return OSQueryResult(
                query=sql,
                rows=[],
                status="error",
                messages=[str(e)]
            )
    
    def get_agent_processes(self) -> List[Dict]:
        """Get all processes related to AI agents"""
        result = self.query("""
            SELECT p.pid, p.name, p.path, p.cmdline, p.cwd, 
                   p.uid, u.username, p.start_time, p.resident_size
            FROM processes p 
            LEFT JOIN users u ON p.uid = u.uid 
            WHERE p.name LIKE '%python%' 
               OR p.name LIKE '%node%' 
               OR p.cmdline LIKE '%agent%'
               OR p.cmdline LIKE '%clawdbot%'
        """)
        return result.rows
    
    def get_network_connections(self, pid: Optional[int] = None) -> List[Dict]:
        """Get network connections, optionally filtered by PID"""
        where_clause = f"WHERE s.pid = {pid}" if pid else ""
        result = self.query(f"""
            SELECT s.pid, p.name, s.remote_address, s.remote_port, 
                   s.local_port, s.state, s.protocol
            FROM process_open_sockets s 
            JOIN processes p ON s.pid = p.pid 
            {where_clause}
            AND s.remote_address NOT IN ('127.0.0.1', '::1', '0.0.0.0', '')
        """)
        return result.rows
    
    def get_file_events(self, path_pattern: str) -> List[Dict]:
        """Get file access events matching a pattern"""
        result = self.query(f"""
            SELECT target_path, action, time, uid
            FROM file_events 
            WHERE target_path LIKE '{path_pattern}'
            ORDER BY time DESC
            LIMIT 100
        """)
        return result.rows
    
    def check_file_integrity(self, paths: List[str]) -> Dict[str, str]:
        """Check SHA256 hashes of specified files"""
        path_list = ",".join(f"'{p}'" for p in paths)
        result = self.query(f"""
            SELECT path, sha256, mtime 
            FROM hash 
            WHERE path IN ({path_list})
        """)
        return {row["path"]: row["sha256"] for row in result.rows}
```

### 3.5 Wazuh API Client

```python
# src/infra_monitor/wazuh_client.py
import httpx
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

@dataclass
class WazuhAlert:
    id: str
    timestamp: datetime
    rule_id: int
    rule_level: int
    rule_description: str
    agent_id: str
    agent_name: str
    data: Dict[str, Any]

class WazuhClient:
    """Client for Wazuh Manager API"""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 55000,
        username: str = "wazuh",
        password: str = "wazuh"
    ):
        self.base_url = f"https://{host}:{port}"
        self.username = username
        self.password = password
        self.token: Optional[str] = None
    
    async def authenticate(self):
        """Get JWT token from Wazuh API"""
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password)
            )
            result = response.json()
            self.token = result["data"]["token"]
    
    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make authenticated request to Wazuh API"""
        if not self.token:
            await self.authenticate()
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                method,
                f"{self.base_url}{endpoint}",
                headers={"Authorization": f"Bearer {self.token}"},
                **kwargs
            )
            return response.json()
    
    async def get_alerts(
        self,
        agent_id: Optional[str] = None,
        rule_group: str = "agentsentinel",
        min_level: int = 6,
        minutes_ago: int = 60
    ) -> List[WazuhAlert]:
        """Fetch recent alerts for AgentSentinel rules"""
        params = {
            "limit": 100,
            "sort": "-timestamp",
            "q": f"rule.groups={rule_group};rule.level>={min_level}"
        }
        
        if agent_id:
            params["agent_list"] = agent_id
        
        result = await self._request("GET", "/alerts", params=params)
        
        alerts = []
        for item in result.get("data", {}).get("affected_items", []):
            alerts.append(WazuhAlert(
                id=item["id"],
                timestamp=datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")),
                rule_id=item["rule"]["id"],
                rule_level=item["rule"]["level"],
                rule_description=item["rule"]["description"],
                agent_id=item["agent"]["id"],
                agent_name=item["agent"]["name"],
                data=item.get("data", {})
            ))
        
        return alerts
    
    async def get_agent_status(self, agent_id: str) -> Dict:
        """Get status of a Wazuh agent"""
        result = await self._request("GET", f"/agents/{agent_id}")
        return result.get("data", {}).get("affected_items", [{}])[0]
    
    async def get_syscheck_files(self, agent_id: str) -> List[Dict]:
        """Get file integrity monitoring results"""
        result = await self._request(
            "GET",
            f"/syscheck/{agent_id}",
            params={"limit": 100, "sort": "-date"}
        )
        return result.get("data", {}).get("affected_items", [])
```

### 3.6 Unified Infrastructure Monitor

```python
# src/infra_monitor/monitor.py
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Callable, Awaitable
from enum import Enum

from .osquery_client import OSQueryClient
from .wazuh_client import WazuhClient, WazuhAlert

class AlertSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class InfraAlert:
    source: str  # "osquery" or "wazuh"
    severity: AlertSeverity
    title: str
    description: str
    timestamp: datetime
    agent_id: Optional[str] = None
    data: dict = field(default_factory=dict)
    
    @property
    def is_critical(self) -> bool:
        return self.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]

class InfrastructureMonitor:
    """Unified infrastructure monitoring using OSquery and Wazuh"""
    
    def __init__(
        self,
        osquery_socket: str = "/var/osquery/osquery.em",
        wazuh_host: str = "localhost",
        wazuh_port: int = 55000,
        wazuh_username: str = "wazuh",
        wazuh_password: str = "wazuh"
    ):
        self.osquery = OSQueryClient(osquery_socket)
        self.wazuh = WazuhClient(wazuh_host, wazuh_port, wazuh_username, wazuh_password)
        
        self.alert_handlers: List[Callable[[InfraAlert], Awaitable[None]]] = []
        self.known_file_hashes: dict[str, str] = {}
        self.baseline_connections: set[str] = set()
        
        self._monitoring = False
    
    def add_alert_handler(self, handler: Callable[[InfraAlert], Awaitable[None]]):
        """Register a handler for infrastructure alerts"""
        self.alert_handlers.append(handler)
    
    async def _emit_alert(self, alert: InfraAlert):
        """Send alert to all registered handlers"""
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                print(f"Alert handler error: {e}")
    
    def establish_baseline(self, config_files: List[str]):
        """Establish baseline file hashes and network connections"""
        # File integrity baseline
        self.known_file_hashes = self.osquery.check_file_integrity(config_files)
        
        # Network connection baseline
        connections = self.osquery.get_network_connections()
        for conn in connections:
            key = f"{conn['remote_address']}:{conn['remote_port']}"
            self.baseline_connections.add(key)
    
    async def check_file_integrity(self, paths: List[str]) -> List[InfraAlert]:
        """Check if monitored files have been modified"""
        alerts = []
        current_hashes = self.osquery.check_file_integrity(paths)
        
        for path, hash_value in current_hashes.items():
            if path in self.known_file_hashes:
                if hash_value != self.known_file_hashes[path]:
                    alert = InfraAlert(
                        source="osquery",
                        severity=AlertSeverity.CRITICAL,
                        title="Configuration file modified",
                        description=f"File {path} has been modified",
                        timestamp=datetime.utcnow(),
                        data={
                            "path": path,
                            "old_hash": self.known_file_hashes[path],
                            "new_hash": hash_value
                        }
                    )
                    alerts.append(alert)
                    await self._emit_alert(alert)
        
        return alerts
    
    async def check_network_anomalies(self) -> List[InfraAlert]:
        """Detect new or suspicious network connections"""
        alerts = []
        connections = self.osquery.get_network_connections()
        
        suspicious_ports = {4444, 5555, 6666, 1337, 31337, 8888}
        
        for conn in connections:
            key = f"{conn['remote_address']}:{conn['remote_port']}"
            
            # Check for new connections
            if key not in self.baseline_connections:
                severity = AlertSeverity.MEDIUM
                
                # Elevate severity for suspicious ports
                if int(conn['remote_port']) in suspicious_ports:
                    severity = AlertSeverity.HIGH
                
                alert = InfraAlert(
                    source="osquery",
                    severity=severity,
                    title="New outbound connection detected",
                    description=f"Process {conn['name']} connected to {key}",
                    timestamp=datetime.utcnow(),
                    data=conn
                )
                alerts.append(alert)
                await self._emit_alert(alert)
        
        return alerts
    
    async def check_wazuh_alerts(self) -> List[InfraAlert]:
        """Fetch and process recent Wazuh alerts"""
        alerts = []
        
        try:
            wazuh_alerts = await self.wazuh.get_alerts(rule_group="agentsentinel")
            
            for wa in wazuh_alerts:
                # Map Wazuh levels to our severity
                if wa.rule_level >= 12:
                    severity = AlertSeverity.CRITICAL
                elif wa.rule_level >= 10:
                    severity = AlertSeverity.HIGH
                elif wa.rule_level >= 7:
                    severity = AlertSeverity.MEDIUM
                else:
                    severity = AlertSeverity.LOW
                
                alert = InfraAlert(
                    source="wazuh",
                    severity=severity,
                    title=wa.rule_description,
                    description=f"Wazuh rule {wa.rule_id} triggered",
                    timestamp=wa.timestamp,
                    agent_id=wa.agent_id,
                    data=wa.data
                )
                alerts.append(alert)
                await self._emit_alert(alert)
        
        except Exception as e:
            print(f"Error fetching Wazuh alerts: {e}")
        
        return alerts
    
    async def run_security_scan(self) -> dict:
        """Run a comprehensive security scan"""
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {},
            "alerts": [],
            "summary": {}
        }
        
        # Check agent processes
        processes = self.osquery.get_agent_processes()
        results["checks"]["agent_processes"] = {
            "count": len(processes),
            "processes": processes
        }
        
        # Check file integrity
        file_alerts = await self.check_file_integrity(list(self.known_file_hashes.keys()))
        results["alerts"].extend([a.__dict__ for a in file_alerts])
        
        # Check network
        network_alerts = await self.check_network_anomalies()
        results["alerts"].extend([a.__dict__ for a in network_alerts])
        
        # Check Wazuh
        wazuh_alerts = await self.check_wazuh_alerts()
        results["alerts"].extend([a.__dict__ for a in wazuh_alerts])
        
        # Summary
        all_alerts = file_alerts + network_alerts + wazuh_alerts
        results["summary"] = {
            "total_alerts": len(all_alerts),
            "critical": len([a for a in all_alerts if a.severity == AlertSeverity.CRITICAL]),
            "high": len([a for a in all_alerts if a.severity == AlertSeverity.HIGH]),
            "status": "compromised" if any(a.is_critical for a in all_alerts) else "healthy"
        }
        
        return results
    
    async def start_continuous_monitoring(self, interval_seconds: int = 60):
        """Start continuous monitoring loop"""
        self._monitoring = True
        
        while self._monitoring:
            await self.run_security_scan()
            await asyncio.sleep(interval_seconds)
    
    def stop_monitoring(self):
        """Stop the monitoring loop"""
        self._monitoring = False
```

---

## Setup Scripts

### 3.7 Wazuh Installation Script

```bash
#!/bin/bash
# scripts/setup_wazuh.sh

set -e

echo "Installing Wazuh Agent..."

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

apt-get update
apt-get install -y wazuh-agent

# Configure agent
WAZUH_MANAGER=${WAZUH_MANAGER:-"localhost"}
sed -i "s|MANAGER_IP|$WAZUH_MANAGER|g" /var/ossec/etc/ossec.conf

# Copy custom rules
cp configs/wazuh/rules/agentsentinel_rules.xml /var/ossec/etc/rules/
cp configs/wazuh/decoders/agentsentinel_decoders.xml /var/ossec/etc/decoders/

# Enable and start
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "Wazuh Agent installed and configured!"
```

### 3.8 OSquery Installation Script

```bash
#!/bin/bash
# scripts/setup_osquery.sh

set -e

echo "Installing OSquery..."

# Add OSquery repository
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'

apt-get update
apt-get install -y osquery

# Copy configuration
mkdir -p /etc/osquery
cp configs/osquery/agentsentinel.conf /etc/osquery/osquery.conf

# Enable file events (requires auditd)
apt-get install -y auditd
auditctl -a always,exit -F arch=b64 -S open -S openat -k osquery_file_events

# Enable and start
systemctl enable osqueryd
systemctl start osqueryd

echo "OSquery installed and configured!"
```

---

## Deliverables

- [ ] `configs/osquery/agentsentinel.conf` - OSquery configuration
- [ ] `configs/wazuh/rules/agentsentinel_rules.xml` - Custom Wazuh rules
- [ ] `configs/wazuh/decoders/agentsentinel_decoders.xml` - Custom decoders
- [ ] `src/infra_monitor/osquery_client.py` - OSquery client
- [ ] `src/infra_monitor/wazuh_client.py` - Wazuh API client
- [ ] `src/infra_monitor/monitor.py` - Unified infrastructure monitor
- [ ] `scripts/setup_wazuh.sh` - Wazuh installation script
- [ ] `scripts/setup_osquery.sh` - OSquery installation script
- [ ] Integration tests with mock data

---

## Next Phase

Proceed to [Phase 4: Red Team Suite](./05-PHASE-4-RED-TEAM.md)
