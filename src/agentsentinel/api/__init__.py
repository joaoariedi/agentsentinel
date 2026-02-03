"""
AgentSentinel API - Unified REST API Server

Provides HTTP endpoints for all AgentSentinel security features:
- Input Shield analysis
- Canary token management
- Behavior monitoring
- Infrastructure scanning
- Red team auditing

Example:
    >>> from agentsentinel.api import create_app
    >>> app = create_app()
    >>> # Run with: uvicorn agentsentinel.api.main:app
"""

from .main import app, create_app, main

__all__ = ["app", "create_app", "main"]
