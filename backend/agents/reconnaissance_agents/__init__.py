"""
Reconnaissance Agents
====================

This module contains all reconnaissance and information gathering agents.
These agents are responsible for:
- Subdomain discovery
- Port scanning  
- Service detection
- OSINT gathering
- Asset discovery
- Certificate transparency
- DNS enumeration
"""

from .subfinder_agent import SubfinderAgent
from .amass_agent import AmassAgent
from .assetfinder_agent import AssetFinderAgent
from .masscan_agent import MasscanAgent
from .naabu_agent import NaabuAgent
from .httpx_agent import HttpxAgent
from .osint_agent import OSINTAgent
from .github_agent import GitHubAgent
from .gau_agent import GAUAgent
from .katana_agent import KatanaAgent
from .paramspider_agent import ParamSpiderAgent
from .sslmate_agent import SSLMateAgent
from .dnstwist_agent import DNSTwistAgent

__all__ = [
    'SubfinderAgent',
    'AmassAgent', 
    'AssetFinderAgent',
    'MasscanAgent',
    'NaabuAgent',
    'HttpxAgent',
    'OSINTAgent',
    'GitHubAgent',
    'GAUAgent',
    'KatanaAgent',
    'ParamSpiderAgent',
    'SSLMateAgent',
    'DNSTwistAgent'
]

# Agent categories for the orchestrator
RECONNAISSANCE_AGENTS = {
    'subdomain_discovery': [SubfinderAgent, AmassAgent, AssetFinderAgent],
    'port_scanning': [MasscanAgent, NaabuAgent],
    'service_detection': [HttpxAgent],
    'osint_gathering': [OSINTAgent, GitHubAgent],
    'url_discovery': [GAUAgent, KatanaAgent, ParamSpiderAgent],
    'certificate_analysis': [SSLMateAgent],
    'phishing_detection': [DNSTwistAgent]
}
