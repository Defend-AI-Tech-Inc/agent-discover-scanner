"""AgentDiscover Scanner - Detect AI Agents and Shadow AI across 4 layers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agent-discover-scanner")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = ["__version__"]
