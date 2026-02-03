"""
Transaction Simulator

Simulates Solana transactions before signing to detect
potentially harmful operations like wallet drains or scam interactions.
"""

from dataclasses import dataclass, field
from typing import Optional

import httpx


@dataclass
class SimulationResult:
    """Result of transaction simulation"""

    success: bool
    error: Optional[str] = None

    # Balance changes
    sender_balance_change: float = 0.0
    receiver_balance_change: float = 0.0
    fee: float = 0.0

    # Token changes
    tokens_sent: list[dict] = field(default_factory=list)
    tokens_received: list[dict] = field(default_factory=list)

    # Risk indicators
    interacts_with_known_scam: bool = False
    drains_wallet: bool = False
    unlimited_approval: bool = False

    @property
    def is_risky(self) -> bool:
        """Check if any risk indicators are present"""
        return (
            self.interacts_with_known_scam
            or self.drains_wallet
            or self.unlimited_approval
        )

    @property
    def risk_summary(self) -> list[str]:
        """Get list of active risk indicators"""
        risks = []
        if self.interacts_with_known_scam:
            risks.append("Interacts with known scam address")
        if self.drains_wallet:
            risks.append("Transaction drains wallet")
        if self.unlimited_approval:
            risks.append("Grants unlimited token approval")
        return risks


@dataclass
class RiskAnalysis:
    """Result of quick risk analysis"""

    risks: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    should_block: bool = False
    require_confirmation: bool = False


class TransactionSimulator:
    """Simulates Solana transactions before signing"""

    def __init__(
        self,
        rpc_url: str = "https://api.mainnet-beta.solana.com",
        timeout: float = 30.0,
    ) -> None:
        """
        Initialize the transaction simulator.

        Args:
            rpc_url: Solana RPC endpoint URL
            timeout: Request timeout in seconds
        """
        self.rpc_url = rpc_url
        self.timeout = timeout
        self.known_scam_addresses: set[str] = set()

    def add_scam_address(self, address: str) -> None:
        """Add an address to the known scam list"""
        self.known_scam_addresses.add(address)

    def add_scam_addresses(self, addresses: list[str]) -> None:
        """Add multiple addresses to the known scam list"""
        self.known_scam_addresses.update(addresses)

    def is_known_scam(self, address: str) -> bool:
        """Check if an address is a known scam"""
        return address in self.known_scam_addresses

    async def simulate(
        self,
        transaction_base64: str,
        wallet_address: str,
    ) -> SimulationResult:
        """
        Simulate a transaction and analyze the outcome.

        Args:
            transaction_base64: Base64-encoded transaction
            wallet_address: The wallet address initiating the transaction

        Returns:
            SimulationResult with balance changes and risk indicators
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Use Solana's simulateTransaction RPC
                response = await client.post(
                    self.rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "simulateTransaction",
                        "params": [
                            transaction_base64,
                            {
                                "encoding": "base64",
                                "commitment": "confirmed",
                                "replaceRecentBlockhash": True,
                            },
                        ],
                    },
                )

                result = response.json()

                if "error" in result:
                    return SimulationResult(
                        success=False,
                        error=result["error"].get("message", str(result["error"])),
                    )

                sim_result = result.get("result", {}).get("value", {})

                if sim_result.get("err"):
                    return SimulationResult(
                        success=False,
                        error=str(sim_result["err"]),
                    )

                # Parse simulation logs and account changes
                # This is a simplified implementation - a full implementation would
                # parse the account changes and logs to extract detailed balance changes
                return self._parse_simulation_result(sim_result, wallet_address)

        except httpx.TimeoutException:
            return SimulationResult(
                success=False,
                error="Transaction simulation timed out",
            )
        except httpx.RequestError as e:
            return SimulationResult(
                success=False,
                error=f"RPC request failed: {str(e)}",
            )
        except Exception as e:
            return SimulationResult(
                success=False,
                error=f"Simulation failed: {str(e)}",
            )

    def _parse_simulation_result(
        self,
        sim_result: dict,
        wallet_address: str,
    ) -> SimulationResult:
        """Parse raw simulation result into structured format"""
        # Extract logs for analysis
        logs = sim_result.get("logs", [])

        # Extract account changes
        accounts = sim_result.get("accounts", [])

        # Calculate fee from units consumed
        units_consumed = sim_result.get("unitsConsumed", 0)
        # Approximate fee (actual calculation depends on priority fees)
        fee = units_consumed * 0.000001  # Rough estimate

        # This is where you'd implement detailed parsing
        # For now, return a successful simulation with basic info
        return SimulationResult(
            success=True,
            fee=fee,
        )

    async def analyze_risk(
        self,
        destination: str,
        amount: float,
        wallet_balance: float,
    ) -> RiskAnalysis:
        """
        Perform quick risk analysis without full simulation.

        Args:
            destination: Destination address
            amount: Amount to transfer
            wallet_balance: Current wallet balance

        Returns:
            RiskAnalysis with risk indicators and recommendations
        """
        risks: list[str] = []
        risk_score = 0.0

        # Check if destination is known scam
        if destination in self.known_scam_addresses:
            risks.append("Destination is a known scam address")
            risk_score = 1.0

        # Check if draining wallet
        if wallet_balance > 0 and amount >= wallet_balance * 0.9:
            percentage = (amount / wallet_balance) * 100
            risks.append(f"Transaction would drain {percentage:.1f}% of wallet")
            risk_score = max(risk_score, 0.8)

        # Large transaction threshold (configurable)
        large_tx_threshold = 100  # SOL
        if amount > large_tx_threshold:
            risks.append(f"Large transaction: {amount} SOL")
            risk_score = max(risk_score, 0.5)

        # Very large transactions get extra scrutiny
        if amount > large_tx_threshold * 10:
            risks.append(f"Very large transaction: {amount} SOL")
            risk_score = max(risk_score, 0.7)

        return RiskAnalysis(
            risks=risks,
            risk_score=risk_score,
            should_block=risk_score >= 0.8,
            require_confirmation=risk_score >= 0.5,
        )

    async def verify_destination(self, address: str) -> dict:
        """
        Verify a destination address.

        Args:
            address: The address to verify

        Returns:
            dict with verification results
        """
        result = {
            "address": address,
            "is_known_scam": address in self.known_scam_addresses,
            "exists": False,
            "is_program": False,
            "balance": 0.0,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Get account info
                response = await client.post(
                    self.rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getAccountInfo",
                        "params": [
                            address,
                            {"encoding": "base64"},
                        ],
                    },
                )

                data = response.json()
                account_info = data.get("result", {}).get("value")

                if account_info:
                    result["exists"] = True
                    result["is_program"] = account_info.get("executable", False)
                    # Balance in lamports, convert to SOL
                    result["balance"] = account_info.get("lamports", 0) / 1e9

        except Exception:
            pass  # Return default result on error

        return result
