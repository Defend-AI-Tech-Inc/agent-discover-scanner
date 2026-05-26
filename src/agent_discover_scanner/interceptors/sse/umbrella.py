from agent_discover_scanner.interceptors.base import NetworkInterceptor


class UmbrellaInterceptor(NetworkInterceptor):
    """Detects Cisco Umbrella Roaming Client SSE proxy."""

    @property
    def vendor(self) -> str:
        return "Cisco Umbrella"

    @property
    def process_names(self) -> list[str]:
        return ["Umbrella_RC"]

    @property
    def env_var_patterns(self) -> list[str]:
        return ["UMBRELLA_", "CISCO_UMBRELLA_"]
