from agent_discover_scanner.interceptors.base import NetworkInterceptor


class NetskopeInterceptor(NetworkInterceptor):
    """Detects Netskope Client SSE proxy."""

    @property
    def vendor(self) -> str:
        return "Netskope"

    @property
    def process_names(self) -> list[str]:
        return ["nsClientUI", "nssvc"]

    @property
    def env_var_patterns(self) -> list[str]:
        return ["NSS_", "NETSKOPE_"]
