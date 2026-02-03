"""
Wazuh Client - Async REST API client for Wazuh Manager.

Provides integration with Wazuh SIEM for alert fetching,
agent status queries, and file integrity monitoring results.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


@dataclass
class WazuhAlert:
    """Represents a Wazuh security alert."""
    
    id: str
    timestamp: datetime
    rule_id: int
    rule_level: int
    rule_description: str
    agent_id: str
    agent_name: str
    data: dict[str, Any] = field(default_factory=dict)
    groups: list[str] = field(default_factory=list)
    
    @property
    def is_critical(self) -> bool:
        """Check if alert is critical (level >= 12)."""
        return self.rule_level >= 12
    
    @property
    def is_high(self) -> bool:
        """Check if alert is high priority (level >= 10)."""
        return self.rule_level >= 10
    
    @property
    def is_agentsentinel(self) -> bool:
        """Check if alert is from AgentSentinel rules."""
        return "agentsentinel" in self.groups
    
    @classmethod
    def from_api_response(cls, item: dict[str, Any]) -> WazuhAlert:
        """Create WazuhAlert from API response item."""
        rule = item.get("rule", {})
        agent = item.get("agent", {})
        
        # Parse timestamp
        timestamp_str = item.get("timestamp", "")
        try:
            timestamp = datetime.fromisoformat(
                timestamp_str.replace("Z", "+00:00")
            )
        except (ValueError, AttributeError):
            timestamp = datetime.now(timezone.utc)
        
        return cls(
            id=item.get("id", ""),
            timestamp=timestamp,
            rule_id=int(rule.get("id", 0)),
            rule_level=int(rule.get("level", 0)),
            rule_description=rule.get("description", ""),
            agent_id=agent.get("id", ""),
            agent_name=agent.get("name", ""),
            data=item.get("data", {}),
            groups=rule.get("groups", []),
        )


@dataclass
class WazuhAgentInfo:
    """Information about a Wazuh agent."""
    
    id: str
    name: str
    ip: str
    status: str
    os_name: str
    os_version: str
    version: str
    last_keep_alive: Optional[datetime] = None
    
    @property
    def is_active(self) -> bool:
        return self.status == "active"
    
    @classmethod
    def from_api_response(cls, item: dict[str, Any]) -> WazuhAgentInfo:
        """Create WazuhAgentInfo from API response."""
        os_info = item.get("os", {})
        
        last_ka_str = item.get("lastKeepAlive")
        last_ka = None
        if last_ka_str:
            try:
                last_ka = datetime.fromisoformat(
                    last_ka_str.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                pass
        
        return cls(
            id=item.get("id", ""),
            name=item.get("name", ""),
            ip=item.get("ip", ""),
            status=item.get("status", "unknown"),
            os_name=os_info.get("name", ""),
            os_version=os_info.get("version", ""),
            version=item.get("version", ""),
            last_keep_alive=last_ka,
        )


class WazuhClientError(Exception):
    """Error from Wazuh API operations."""
    pass


class WazuhClient:
    """Async client for Wazuh Manager API."""
    
    DEFAULT_PORT = 55000
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = DEFAULT_PORT,
        username: str = "wazuh",
        password: str = "wazuh",
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ):
        """
        Initialize Wazuh API client.
        
        Args:
            host: Wazuh Manager hostname or IP
            port: Wazuh API port (default: 55000)
            username: API username
            password: API password
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for Wazuh client. "
                "Install with: pip install httpx"
            )
        
        self.base_url = f"https://{host}:{port}"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
    
    def _get_ssl_context(self) -> ssl.SSLContext:
        """Get SSL context for connections."""
        if self.verify_ssl:
            return ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
    
    async def authenticate(self) -> str:
        """
        Authenticate and get JWT token.
        
        Returns:
            JWT token string
            
        Raises:
            WazuhClientError: If authentication fails
        """
        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
        ) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/security/user/authenticate",
                    auth=(self.username, self.password),
                )
                response.raise_for_status()
                
                result = response.json()
                self._token = result["data"]["token"]
                # Token typically valid for 15 minutes
                self._token_expiry = datetime.now(timezone.utc) + timedelta(minutes=14)
                
                return self._token
                
            except httpx.HTTPStatusError as e:
                raise WazuhClientError(
                    f"Authentication failed: {e.response.status_code}"
                ) from e
            except Exception as e:
                raise WazuhClientError(f"Authentication error: {e}") from e
    
    async def _ensure_token(self) -> str:
        """Ensure we have a valid token, refreshing if needed."""
        now = datetime.now(timezone.utc)
        
        if self._token and self._token_expiry and now < self._token_expiry:
            return self._token
        
        return await self.authenticate()
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> dict[str, Any]:
        """
        Make authenticated request to Wazuh API.
        
        Args:
            method: HTTP method
            endpoint: API endpoint (e.g., "/agents")
            params: Query parameters
            json_data: JSON body data
            
        Returns:
            API response data
            
        Raises:
            WazuhClientError: If request fails
        """
        token = await self._ensure_token()
        
        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
        ) as client:
            try:
                response = await client.request(
                    method,
                    f"{self.base_url}{endpoint}",
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                    json=json_data,
                )
                response.raise_for_status()
                return response.json()
                
            except httpx.HTTPStatusError as e:
                # Token might have expired, try re-auth once
                if e.response.status_code == 401:
                    self._token = None
                    token = await self.authenticate()
                    
                    response = await client.request(
                        method,
                        f"{self.base_url}{endpoint}",
                        headers={"Authorization": f"Bearer {token}"},
                        params=params,
                        json=json_data,
                    )
                    response.raise_for_status()
                    return response.json()
                
                raise WazuhClientError(
                    f"Request failed: {e.response.status_code} - {e.response.text}"
                ) from e
            except Exception as e:
                raise WazuhClientError(f"Request error: {e}") from e
    
    async def get_alerts(
        self,
        agent_id: Optional[str] = None,
        rule_group: str = "agentsentinel",
        min_level: int = 6,
        limit: int = 100,
        offset: int = 0,
    ) -> list[WazuhAlert]:
        """
        Fetch recent alerts.
        
        Args:
            agent_id: Optional agent ID to filter by
            rule_group: Rule group to filter (default: agentsentinel)
            min_level: Minimum rule level
            limit: Maximum alerts to return
            offset: Pagination offset
            
        Returns:
            List of WazuhAlert objects
        """
        params: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "sort": "-timestamp",
        }
        
        # Build query filter
        q_parts = []
        if rule_group:
            q_parts.append(f"rule.groups={rule_group}")
        if min_level > 0:
            q_parts.append(f"rule.level>={min_level}")
        
        if q_parts:
            params["q"] = ";".join(q_parts)
        
        if agent_id:
            params["agent_list"] = agent_id
        
        result = await self._request("GET", "/alerts", params=params)
        
        items = result.get("data", {}).get("affected_items", [])
        return [WazuhAlert.from_api_response(item) for item in items]
    
    async def get_critical_alerts(
        self,
        minutes_ago: int = 60,
        limit: int = 50,
    ) -> list[WazuhAlert]:
        """
        Get critical alerts (level >= 12) from recent timeframe.
        
        Args:
            minutes_ago: How far back to look
            limit: Maximum alerts
            
        Returns:
            List of critical WazuhAlert objects
        """
        return await self.get_alerts(
            rule_group="",
            min_level=12,
            limit=limit,
        )
    
    async def get_agent_status(self, agent_id: str) -> WazuhAgentInfo:
        """
        Get status of a Wazuh agent.
        
        Args:
            agent_id: Agent ID to query
            
        Returns:
            WazuhAgentInfo object
            
        Raises:
            WazuhClientError: If agent not found
        """
        result = await self._request("GET", f"/agents/{agent_id}")
        items = result.get("data", {}).get("affected_items", [])
        
        if not items:
            raise WazuhClientError(f"Agent {agent_id} not found")
        
        return WazuhAgentInfo.from_api_response(items[0])
    
    async def list_agents(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> list[WazuhAgentInfo]:
        """
        List Wazuh agents.
        
        Args:
            status: Filter by status (active, disconnected, etc.)
            limit: Maximum agents to return
            
        Returns:
            List of WazuhAgentInfo objects
        """
        params: dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        
        result = await self._request("GET", "/agents", params=params)
        items = result.get("data", {}).get("affected_items", [])
        
        return [WazuhAgentInfo.from_api_response(item) for item in items]
    
    async def get_syscheck_files(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Get file integrity monitoring (syscheck) results.
        
        Args:
            agent_id: Agent ID to query
            limit: Maximum results
            
        Returns:
            List of syscheck file dicts
        """
        result = await self._request(
            "GET",
            f"/syscheck/{agent_id}",
            params={"limit": limit, "sort": "-date"},
        )
        return result.get("data", {}).get("affected_items", [])
    
    async def get_manager_info(self) -> dict[str, Any]:
        """
        Get Wazuh Manager information.
        
        Returns:
            Dict with manager info
        """
        result = await self._request("GET", "/manager/info")
        return result.get("data", {}).get("affected_items", [{}])[0]
    
    async def is_available(self) -> bool:
        """
        Check if Wazuh API is available.
        
        Returns:
            True if API is reachable and authentication works
        """
        try:
            await self.authenticate()
            return True
        except WazuhClientError:
            return False
