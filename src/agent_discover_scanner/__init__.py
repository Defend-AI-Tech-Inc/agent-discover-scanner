"""AgentDiscover — Detect AI Agents and Shadow AI across 5 layers."""

import warnings
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agentdiscover")
except PackageNotFoundError:
    __version__ = "0.0.0"

# Emit a DeprecationWarning when the legacy 'agent-discover-scanner' distribution
# is installed alongside this package (i.e. the user still has the stub installed).
try:
    version("agent-discover-scanner")
    warnings.warn(
        "The package 'agent-discover-scanner' is deprecated and will be removed in a "
        "future release. Please migrate: pip install agentdiscover",
        DeprecationWarning,
        stacklevel=2,
    )
except PackageNotFoundError:
    pass

__all__ = ["__version__"]
