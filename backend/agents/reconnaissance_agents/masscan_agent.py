"""
Masscan Agent - Ultra-High-Speed Port Scanner
Professional Internet-scale port scanning with 6 million packets/second capability
"""

import asyncio
import json
import subprocess
import tempfile
import os
from typing import Dict, List, Any, Optional
from loguru import logger
from ipaddress import ip_network, AddressValueError

from agents.base import BaseAgent


class MasscanAgent(BaseAgent):
    """
    Professional Ultra-High-Speed Port Scanner using Masscan
    Designed for Internet-scale reconnaissance and large network discovery
    """
    
    def __init__(self):
        super().__init__("masscan_agent")
        self.tool_command = "masscan"
        self.max_rate = 10000  # Default rate limit for safety
        self.default_ports = "1-65535"  # Full port range
        
    async def scan_ports(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform high-speed port scanning on target
        
        Args:
            target: Target IP, CIDR, or domain
            options: Scanning options (ports, rate, etc.)
            
        Returns:
            Port scanning results with discovered services
        """
        logger.info(f"🚀 Starting Masscan high-speed port scan for {target}")
        
        try:
            # Prepare masscan command
            cmd = [self.tool_command]
            
            # Add target
            cmd.append(target)
            
            # Configure options
            if options:
                # Port specification
                ports = options.get("ports", self.default_ports)
                cmd.extend(["-p", ports])
                
                # Rate limiting
                rate = min(options.get("rate", self.max_rate), 100000)  # Safety cap
                cmd.extend(["--rate", str(rate)])
                
                # Output format
                cmd.extend(["-oJ", "-"])  # JSON output to stdout
                
                # Additional options
                if options.get("ping"):
                    cmd.append("--ping")
                if options.get("banners"):
                    cmd.append("--banners")
                if options.get("source_ip"):
                    cmd.extend(["-S", options["source_ip"]])
                if options.get("interface"):
                    cmd.extend(["-e", options["interface"]])
                if options.get("exclude"):
                    cmd.extend(["--exclude", options["exclude"]])
                if options.get("includefile"):
                    cmd.extend(["--includefile", options["includefile"]])
            else:
                # Default configuration
                cmd.extend(["-p", "1-1000"])  # Top 1000 ports
                cmd.extend(["--rate", str(self.max_rate)])
                cmd.extend(["-oJ", "-"])
            
            # Execute masscan
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                results = self._parse_masscan_output(stdout.decode())
                logger.info(f"✅ Masscan completed for {target} - Found {len(results.get('open_ports', []))} open ports")
                
                return {
                    "success": True,
                    "target": target,
                    "scan_results": results,
                    "command_used": " ".join(cmd),
                    "timestamp": self._get_timestamp()
                }
            else:
                error_msg = stderr.decode().strip()
                logger.error(f"❌ Masscan scan failed: {error_msg}")
                return {
                    "success": False,
                    "target": target,
                    "error": error_msg,
                    "timestamp": self._get_timestamp()
                }
                
        except FileNotFoundError:
            logger.error("❌ Masscan not found - install with: brew install masscan")
            return await self._fallback_port_scan(target, options)
        except Exception as e:
            logger.error(f"❌ Masscan scan error: {e}")
            return await self._fallback_port_scan(target, options)
    
    def _parse_masscan_output(self, output: str) -> Dict[str, Any]:
        """Parse masscan JSON output"""
        results = {
            "open_ports": [],
            "total_ports": 0,
            "unique_ips": set(),
            "services": {},
            "statistics": {}
        }
        
        try:
            lines = output.strip().split('\n')
            for line in lines:
                if line.strip() and line.startswith('{'):
                    try:
                        entry = json.loads(line)
                        
                        if entry.get("ip") and entry.get("ports"):
                            ip = entry["ip"]
                            results["unique_ips"].add(ip)
                            
                            for port_info in entry["ports"]:
                                port = port_info.get("port")
                                proto = port_info.get("proto", "tcp")
                                status = port_info.get("status", "open")
                                service = port_info.get("service", "unknown")
                                
                                port_entry = {
                                    "ip": ip,
                                    "port": port,
                                    "protocol": proto,
                                    "status": status,
                                    "service": service
                                }
                                
                                results["open_ports"].append(port_entry)
                                
                                # Track services
                                service_key = f"{proto}/{port}"
                                if service_key not in results["services"]:
                                    results["services"][service_key] = []
                                results["services"][service_key].append(ip)
                                
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.debug(f"Error parsing masscan output: {e}")
        
        # Convert sets to lists for JSON serialization
        results["unique_ips"] = list(results["unique_ips"])
        results["total_ports"] = len(results["open_ports"])
        
        # Generate statistics
        results["statistics"] = {
            "total_open_ports": len(results["open_ports"]),
            "unique_hosts": len(results["unique_ips"]),
            "unique_services": len(results["services"]),
            "tcp_ports": len([p for p in results["open_ports"] if p.get("protocol") == "tcp"]),
            "udp_ports": len([p for p in results["open_ports"] if p.get("protocol") == "udp"])
        }
        
        return results
    
    async def _fallback_port_scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Fallback port scanning using Python socket connections
        """
        logger.info(f"🔧 Using fallback port scanning for {target}")
        
        try:
            import socket
            from concurrent.futures import ThreadPoolExecutor
            
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
            
            if options and options.get("ports"):
                # Parse port specification
                port_spec = options["ports"]
                if "-" in port_spec:
                    start, end = map(int, port_spec.split("-"))
                    ports_to_scan = list(range(start, min(end + 1, 65536)))
                else:
                    ports_to_scan = [int(p) for p in port_spec.split(",")]
            else:
                ports_to_scan = common_ports
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    return port if result == 0 else None
                except:
                    return None
            
            # Scan ports concurrently
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(scan_port, port) for port in ports_to_scan]
                open_ports = [future.result() for future in futures if future.result() is not None]
            
            results = {
                "open_ports": [{"ip": target, "port": port, "protocol": "tcp", "status": "open", "service": "unknown"} for port in open_ports],
                "total_ports": len(open_ports),
                "unique_ips": [target],
                "services": {},
                "statistics": {
                    "total_open_ports": len(open_ports),
                    "unique_hosts": 1,
                    "unique_services": len(open_ports),
                    "tcp_ports": len(open_ports),
                    "udp_ports": 0
                }
            }
            
            return {
                "success": True,
                "target": target,
                "scan_results": results,
                "method": "fallback_socket_scan",
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"❌ Fallback port scan failed: {e}")
            return {
                "success": False,
                "target": target,
                "error": f"Fallback scan failed: {str(e)}",
                "timestamp": self._get_timestamp()
            }
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        return await self.scan_ports(target, config)
    
    async def bulk_scan(
        self,
        targets: List[str],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform bulk port scanning on multiple targets
        """
        logger.info(f"🚀 Starting bulk Masscan for {len(targets)} targets")
        
        results = []
        for target in targets:
            result = await self.scan_ports(target, options)
            results.append(result)
            
            # Small delay between scans
            await asyncio.sleep(0.5)
        
        return {
            "success": True,
            "total_targets": len(targets),
            "results": results,
            "summary": self._generate_bulk_summary(results),
            "timestamp": self._get_timestamp()
        }
    
    def _generate_bulk_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of bulk scanning results"""
        total_targets = len(results)
        successful_scans = sum(1 for r in results if r.get("success"))
        total_ports = sum(len(r.get("scan_results", {}).get("open_ports", [])) for r in results if r.get("success"))
        
        return {
            "total_targets": total_targets,
            "successful_scans": successful_scans,
            "failed_scans": total_targets - successful_scans,
            "total_open_ports": total_ports,
            "success_rate": f"{(successful_scans/total_targets)*100:.1f}%" if total_targets > 0 else "0%"
        }
    
    def get_scan_info(self) -> Dict[str, Any]:
        """Get information about this scanning agent"""
        return {
            "name": "Masscan Ultra-High-Speed Port Scanner",
            "description": "Internet-scale port scanning with 6 million packets/second capability",
            "capabilities": [
                "Ultra-High-Speed Port Scanning",
                "Internet-Scale Network Discovery", 
                "Large-Scale Reconnaissance",
                "Custom Rate Limiting",
                "Multiple Output Formats",
                "Banner Grabbing",
                "Ping Scanning",
                "Bulk Target Processing"
            ],
            "supported_targets": ["IP addresses", "CIDR ranges", "domain names"],
            "output_formats": ["JSON", "structured"],
            "tool_version": "masscan",
            "agent_version": "1.0.0",
            "max_rate": "100,000 packets/second (safety limited)",
            "default_ports": "1-1000 (customizable to full range)"
        }


