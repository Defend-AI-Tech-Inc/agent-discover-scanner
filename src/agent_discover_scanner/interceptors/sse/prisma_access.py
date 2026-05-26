from agent_discover_scanner.interceptors.base import NetworkInterceptor


class PrismaAccessInterceptor(NetworkInterceptor):
    """Detects Palo Alto Networks Prisma Access (GlobalProtect) SSE proxy."""

    @property
    def vendor(self) -> str:
        return "Palo Alto Prisma Access"

    @property
    def process_names(self) -> list[str]:
        return ["PanGPS", "pangps"]

    @property
    def env_var_patterns(self) -> list[str]:
        return ["PANGPS_", "PALOALTO_"]
