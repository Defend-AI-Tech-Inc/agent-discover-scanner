from agent_discover_scanner.interceptors.base import NetworkInterceptor


class ZscalerInterceptor(NetworkInterceptor):
    """Detects Zscaler Client Connector (ZCC) SSE proxy."""

    @property
    def vendor(self) -> str:
        return "Zscaler"

    @property
    def process_names(self) -> list[str]:
        return ["ZSATunnel", "ZSAService", "ZSAUpdater"]

    @property
    def env_var_patterns(self) -> list[str]:
        return ["ZIA_CLOUD", "ZSATUNNEL_", "ZSCALER_"]
