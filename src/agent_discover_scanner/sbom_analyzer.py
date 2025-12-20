"""
SBOM (Software Bill of Materials) analyzer for detecting AI/ML dependencies.
"""
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class DependencyFinding:
    """Represents a risky dependency detected in SBOM."""
    package_name: str
    version: str
    ecosystem: str  # "pypi", "npm", "docker"
    risk_level: str  # "high", "medium", "low"
    reason: str


class SBOMAnalyzer:
    """Analyze dependencies for AI/ML frameworks that indicate agent usage."""
    
    # High-risk AI/ML packages that indicate autonomous agents
    HIGH_RISK_PACKAGES = {
        "pypi": {
            "langchain": "LangChain - Agent orchestration framework",
            "langchain-core": "LangChain - Agent orchestration framework",
            "langchain-community": "LangChain - Community integrations",
            "autogen": "Microsoft AutoGen - Multi-agent framework",
            "crewai": "CrewAI - Agent collaboration framework",
            "semantic-kernel": "Microsoft Semantic Kernel - Agent framework",
            "haystack-ai": "Haystack - Agent and RAG framework",
            "llama-index": "LlamaIndex - Data framework for LLM agents",
        },
        "npm": {
            "langchain": "LangChain.js - Agent orchestration",
            "@langchain/core": "LangChain.js core",
            "ai": "Vercel AI SDK",
            "autogen": "AutoGen for JavaScript",
        }
    }
    
    # Medium-risk packages (LLM clients that could be used for agents)
    MEDIUM_RISK_PACKAGES = {
        "pypi": {
            "openai": "OpenAI API client - Could indicate Shadow AI",
            "anthropic": "Anthropic API client - Could indicate Shadow AI",
            "google-generativeai": "Google AI client",
            "cohere": "Cohere API client",
        },
        "npm": {
            "openai": "OpenAI API client",
            "@anthropic-ai/sdk": "Anthropic API client",
        }
    }
    
    @classmethod
    def generate_sbom(cls, target: str, output_path: Optional[Path] = None) -> Optional[Dict]:
        """
        Generate SBOM using syft.
        
        Args:
            target: Path to directory, file, or Docker image
            output_path: Optional path to save SBOM JSON
        
        Returns:
            SBOM as dictionary, or None if generation fails
        """
        try:
            # Run syft to generate SBOM in JSON format
            cmd = ["syft", "scan", target, "-o", "json"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                return None
            
            sbom = json.loads(result.stdout)
            
            # Save to file if requested
            if output_path:
                with open(output_path, 'w') as f:
                    json.dump(sbom, f, indent=2)
            
            return sbom
            
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return None
    
    @classmethod
    def analyze_sbom(cls, sbom: Dict) -> List[DependencyFinding]:
        """
        Analyze SBOM for risky AI/ML dependencies.
        
        Args:
            sbom: SBOM dictionary from syft
        
        Returns:
            List of DependencyFinding objects
        """
        findings = []
        
        if not sbom or "artifacts" not in sbom:
            return findings
        
        for artifact in sbom["artifacts"]:
            package_name = artifact.get("name", "").lower()
            version = artifact.get("version", "unknown")
            
            # Determine ecosystem
            artifact_type = artifact.get("type", "")
            if "python" in artifact_type.lower():
                ecosystem = "pypi"
            elif any(x in artifact_type.lower() for x in ["npm", "node", "javascript"]):
                ecosystem = "npm"
            else:
                ecosystem = "unknown"
            
            # Check against high-risk packages
            if ecosystem in cls.HIGH_RISK_PACKAGES:
                for risky_pkg, reason in cls.HIGH_RISK_PACKAGES[ecosystem].items():
                    if risky_pkg in package_name:
                        finding = DependencyFinding(
                            package_name=artifact.get("name"),
                            version=version,
                            ecosystem=ecosystem,
                            risk_level="high",
                            reason=reason
                        )
                        findings.append(finding)
                        break
            
            # Check against medium-risk packages
            if ecosystem in cls.MEDIUM_RISK_PACKAGES:
                for risky_pkg, reason in cls.MEDIUM_RISK_PACKAGES[ecosystem].items():
                    if risky_pkg in package_name:
                        finding = DependencyFinding(
                            package_name=artifact.get("name"),
                            version=version,
                            ecosystem=ecosystem,
                            risk_level="medium",
                            reason=reason
                        )
                        findings.append(finding)
                        break
        
        return findings
    
    @classmethod
    def scan_directory(cls, directory: Path) -> List[DependencyFinding]:
        """
        Convenience method to generate SBOM and analyze a directory.
        
        Args:
            directory: Path to scan
        
        Returns:
            List of findings
        """
        sbom = cls.generate_sbom(str(directory))
        if not sbom:
            return []
        
        return cls.analyze_sbom(sbom)


def analyze_requirements_txt(requirements_path: Path) -> List[DependencyFinding]:
    """
    Quick analysis of requirements.txt without full SBOM generation.
    
    Args:
        requirements_path: Path to requirements.txt
    
    Returns:
        List of findings
    """
    findings = []
    
    if not requirements_path.exists():
        return findings
    
    content = requirements_path.read_text()
    
    for line in content.split('\n'):
        line = line.strip().lower()
        if not line or line.startswith('#'):
            continue
        
        # Extract package name (handle ==, >=, etc.)
        package = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
        
        # Check against our risk databases
        for risky_pkg, reason in SBOMAnalyzer.HIGH_RISK_PACKAGES["pypi"].items():
            if risky_pkg in package:
                finding = DependencyFinding(
                    package_name=package,
                    version="unknown",
                    ecosystem="pypi",
                    risk_level="high",
                    reason=reason
                )
                findings.append(finding)
                break
        
        for risky_pkg, reason in SBOMAnalyzer.MEDIUM_RISK_PACKAGES["pypi"].items():
            if risky_pkg in package:
                finding = DependencyFinding(
                    package_name=package,
                    version="unknown",
                    ecosystem="pypi",
                    risk_level="medium",
                    reason=reason
                )
                findings.append(finding)
                break
    
    return findings


def analyze_package_json(package_path: Path) -> List[DependencyFinding]:
    """
    Quick analysis of package.json without full SBOM generation.
    
    Args:
        package_path: Path to package.json
    
    Returns:
        List of findings
    """
    findings = []
    
    if not package_path.exists():
        return findings
    
    try:
        data = json.loads(package_path.read_text())
        
        # Check dependencies and devDependencies
        all_deps = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))
        
        for package, version in all_deps.items():
            package_lower = package.lower()
            
            # Check against risk databases
            for risky_pkg, reason in SBOMAnalyzer.HIGH_RISK_PACKAGES["npm"].items():
                if risky_pkg in package_lower:
                    finding = DependencyFinding(
                        package_name=package,
                        version=version,
                        ecosystem="npm",
                        risk_level="high",
                        reason=reason
                    )
                    findings.append(finding)
                    break
            
            for risky_pkg, reason in SBOMAnalyzer.MEDIUM_RISK_PACKAGES["npm"].items():
                if risky_pkg in package_lower:
                    finding = DependencyFinding(
                        package_name=package,
                        version=version,
                        ecosystem="npm",
                        risk_level="medium",
                        reason=reason
                    )
                    findings.append(finding)
                    break
    
    except json.JSONDecodeError:
        pass
    
    return findings
