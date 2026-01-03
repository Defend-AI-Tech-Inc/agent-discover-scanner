"""Map IP addresses to LLM and Vector DB vendors."""

from typing import Optional
import ipaddress


# Known LLM API IP ranges and hostnames
# Order matters: more specific ranges should be checked first!
LLM_VENDORS = {
    "cohere": {
        "name": "Cohere",
        "domains": ["api.cohere.ai"],
        "ip_ranges": [
            "34.96.0.0/16",  # Cohere on Google Cloud (specific subnet)
        ],
    },
    "openai": {
        "name": "OpenAI",
        "domains": ["api.openai.com"],
        "ip_ranges": [
            "162.159.0.0/16",  # Cloudflare (used by OpenAI)
        ],
    },
    "anthropic": {
        "name": "Anthropic",
        "domains": ["api.anthropic.com"],
        "ip_ranges": [
            "160.79.0.0/16",  # Anthropic infrastructure
        ],
    },
    "google": {
        "name": "Google AI (Gemini/VertexAI)",
        "domains": ["generativelanguage.googleapis.com", "aiplatform.googleapis.com"],
        "ip_ranges": [
            "142.250.0.0/15",  # Google Cloud (broader range, check after Cohere)
            "34.64.0.0/10",    # Google Cloud (very broad, last resort)
        ],
    },
    "azure_openai": {
        "name": "Azure OpenAI",
        "domains": ["openai.azure.com"],
        "ip_ranges": [
            "20.0.0.0/8",  # Azure
        ],
    },
    "bedrock": {
        "name": "AWS Bedrock",
        "domains": ["bedrock.amazonaws.com", "bedrock-runtime.amazonaws.com"],
        "ip_ranges": [
            "52.0.0.0/8",   # AWS
            "54.0.0.0/8",   # AWS
        ],
    },
}

VECTOR_DB_VENDORS = {
    "pinecone": {
        "name": "Pinecone",
        "domains": ["pinecone.io"],
        "ip_ranges": [],
    },
    "weaviate": {
        "name": "Weaviate Cloud",
        "domains": ["weaviate.cloud"],
        "ip_ranges": [],
    },
    "qdrant": {
        "name": "Qdrant Cloud",
        "domains": ["qdrant.io"],
        "ip_ranges": [],
    },
}


def identify_vendor(dest_ip: str, dest_port: int = 443) -> Optional[str]:
    """
    Identify LLM/Vector DB vendor from destination IP.
    
    Note: Checks vendors in order, more specific ranges first.
    
    Args:
        dest_ip: Destination IP address
        dest_port: Destination port (default 443)
        
    Returns:
        Vendor name if matched, None otherwise
    """
    if dest_port not in [443, 80]:  # Only check HTTPS/HTTP traffic
        return None
    
    try:
        ip = ipaddress.ip_address(dest_ip)
    except ValueError:
        return None
    
    # Check LLM vendors (order matters - specific first!)
    for vendor_key, vendor_info in LLM_VENDORS.items():
        for ip_range in vendor_info["ip_ranges"]:
            if ip in ipaddress.ip_network(ip_range):
                return vendor_info["name"]
    
    # Check Vector DB vendors
    for vendor_key, vendor_info in VECTOR_DB_VENDORS.items():
        for ip_range in vendor_info["ip_ranges"]:
            if ip in ipaddress.ip_network(ip_range):
                return vendor_info["name"]
    
    return None


def get_all_vendors() -> dict:
    """Get all known vendors."""
    return {**LLM_VENDORS, **VECTOR_DB_VENDORS}
