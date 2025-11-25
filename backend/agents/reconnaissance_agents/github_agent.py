"""
GitHub Intelligence Agent - Repository Analysis
Advanced GitHub repository reconnaissance and security analysis
"""

import asyncio
import json
import base64
from typing import Dict, List, Any, Set, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

from loguru import logger
from agents.base import BaseAgent


@dataclass
class Repository:
    """Repository information"""
    name: str
    full_name: str
    description: str
    url: str
    clone_url: str
    is_private: bool
    is_fork: bool
    stars: int
    forks: int
    size: int
    language: str
    topics: List[str]
    created_at: str
    updated_at: str
    pushed_at: str


@dataclass
class GitHubUser:
    """GitHub user/organization information"""
    login: str
    name: str
    type: str  # User or Organization
    public_repos: int
    followers: int
    following: int
    created_at: str
    company: str
    location: str
    email: str


class GitHubAgent(BaseAgent):
    """
    GitHub Intelligence Agent for comprehensive repository analysis
    Performs OSINT on GitHub repositories, users, and organizations
    """
    
    def __init__(self):
        super().__init__("GitHubAgent")
        self.discovered_repos: List[Repository] = []
        self.github_users: List[GitHubUser] = []
        
        # GitHub API configuration
        self.api_base = "https://api.github.com"
        self.api_token = self._get_github_token()
        self.headers = self._setup_headers()
        
        # Rate limiting
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = datetime.utcnow()
        
        # Search parameters
        self.max_repos_per_org = 100
        self.max_file_size = 1024 * 1024  # 1MB
        
    def _get_github_token(self) -> Optional[str]:
        """Get GitHub API token from environment or configuration"""
        import os
        
        # Try multiple environment variable names
        token_vars = ["GITHUB_TOKEN", "GITHUB_API_TOKEN", "GH_TOKEN"]
        
        for var in token_vars:
            token = os.getenv(var)
            if token:
                logger.info(f"✅ Found GitHub token in {var}")
                return token
        
        logger.warning("⚠️ No GitHub API token found - using anonymous access (limited)")
        return None
    
    def _setup_headers(self) -> Dict[str, str]:
        """Setup HTTP headers for GitHub API"""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Nexus-Hunter-Security-Scanner/1.0"
        }
        
        if self.api_token:
            headers["Authorization"] = f"token {self.api_token}"
        
        return headers
    
    async def execute(self, scan_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Execute comprehensive GitHub intelligence gathering"""
        target_domain = scan_data.get("target", "").replace("http://", "").replace("https://", "").split("/")[0]
        
        logger.info(f"🕵️ Starting GitHub intelligence gathering for {target_domain}")
        
        results = {
            "repositories": [],
            "users": [],
            "organizations": [],
            "sensitive_files": [],
            "secrets_exposed": [],
            "security_issues": [],
            "intelligence_summary": {},
            "metadata": {}
        }
        
        try:
            # Phase 1: Domain-based Repository Discovery
            await self.update_progress("repo_discovery", {
                "status": "Discovering repositories related to target domain",
                "phase": "1/5"
            })
            
            domain_repos = await self._discover_domain_repositories(target_domain)
            results["repositories"].extend(domain_repos)
            
            # Phase 2: Organization Discovery
            if not self.is_cancelled():
                await self.update_progress("org_discovery", {
                    "status": "Identifying related organizations and users",
                    "phase": "2/5"
                })
                
                orgs_and_users = await self._discover_organizations_and_users(target_domain)
                results["organizations"].extend(orgs_and_users["organizations"])
                results["users"].extend(orgs_and_users["users"])
            
            # Phase 3: Repository Content Analysis
            if not self.is_cancelled() and results["repositories"]:
                await self.update_progress("content_analysis", {
                    "status": "Analyzing repository contents for sensitive data",
                    "phase": "3/5"
                })
                
                content_analysis = await self._analyze_repository_contents(results["repositories"][:20])
                results["sensitive_files"] = content_analysis["sensitive_files"]
                results["secrets_exposed"] = content_analysis["secrets"]
            
            # Phase 4: Security Issue Detection
            if not self.is_cancelled():
                await self.update_progress("security_analysis", {
                    "status": "Detecting security issues and vulnerabilities",
                    "phase": "4/5"
                })
                
                security_issues = await self._detect_security_issues(results["repositories"])
                results["security_issues"] = security_issues
            
            # Phase 5: Intelligence Analysis
            await self.update_progress("intelligence", {
                "status": "Generating intelligence summary",
                "phase": "5/5"
            })
            
            results["intelligence_summary"] = self._generate_intelligence_summary(results)
            results["metadata"] = self._generate_metadata(results)
            
            logger.info(f"✅ GitHub intelligence completed: {len(results['repositories'])} repos analyzed")
            return results
            
        except Exception as e:
            logger.error(f"❌ GitHub intelligence failed: {e}")
            raise
    
    async def _discover_domain_repositories(self, domain: str) -> List[Dict[str, Any]]:
        """Discover repositories related to the target domain"""
        repositories = []
        
        import httpx
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Search strategies
            search_queries = [
                f'"{domain}"',
                f'{domain.split(".")[0]}',  # Company name
                f'{domain} in:name',
                f'{domain} in:description',
                f'{domain} in:readme'
            ]
            
            for query in search_queries:
                if self.is_cancelled():
                    break
                
                repos = await self._search_repositories(client, query)
                repositories.extend(repos)
                
                # Rate limiting
                await asyncio.sleep(1)
        
        # Remove duplicates
        seen_repos = set()
        unique_repos = []
        for repo in repositories:
            repo_id = repo.get("id") or repo.get("full_name")
            if repo_id not in seen_repos:
                seen_repos.add(repo_id)
                unique_repos.append(repo)
        
        logger.info(f"📚 Discovered {len(unique_repos)} repositories for {domain}")
        return unique_repos[:self.max_repos_per_org]  # Limit results
    
    async def _search_repositories(self, client: 'httpx.AsyncClient', query: str) -> List[Dict[str, Any]]:
        """Search GitHub repositories"""
        repositories = []
        
        try:
            await self._check_rate_limit(client)
            
            search_url = f"{self.api_base}/search/repositories"
            params = {
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": 50
            }
            
            response = await client.get(search_url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                
                for repo_data in data.get("items", []):
                    repo = self._parse_repository_data(repo_data)
                    if repo:
                        repositories.append(repo)
            
            elif response.status_code == 403:
                logger.warning("⚠️ GitHub API rate limit exceeded")
            
        except Exception as e:
            logger.warning(f"Repository search failed for query '{query}': {e}")
        
        return repositories
    
    def _parse_repository_data(self, repo_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GitHub repository data"""
        try:
            return {
                "id": repo_data.get("id"),
                "name": repo_data.get("name"),
                "full_name": repo_data.get("full_name"),
                "description": repo_data.get("description", ""),
                "url": repo_data.get("html_url"),
                "clone_url": repo_data.get("clone_url"),
                "is_private": repo_data.get("private", False),
                "is_fork": repo_data.get("fork", False),
                "stars": repo_data.get("stargazers_count", 0),
                "forks": repo_data.get("forks_count", 0),
                "size": repo_data.get("size", 0),
                "language": repo_data.get("language", ""),
                "topics": repo_data.get("topics", []),
                "created_at": repo_data.get("created_at"),
                "updated_at": repo_data.get("updated_at"),
                "pushed_at": repo_data.get("pushed_at"),
                "owner": {
                    "login": repo_data.get("owner", {}).get("login"),
                    "type": repo_data.get("owner", {}).get("type")
                }
            }
        except Exception as e:
            logger.warning(f"Failed to parse repository data: {e}")
            return None
    
    async def _discover_organizations_and_users(self, domain: str) -> Dict[str, List[Dict[str, Any]]]:
        """Discover GitHub organizations and users related to domain"""
        organizations = []
        users = []
        
        import httpx
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Search for users/orgs by domain/company name
            company_name = domain.split('.')[0]
            
            search_queries = [
                f'{company_name} type:org',
                f'{company_name} type:user',
                f'"{company_name}" in:name type:org',
                f'"{company_name}" in:login type:user'
            ]
            
            for query in search_queries:
                if self.is_cancelled():
                    break
                
                results = await self._search_users(client, query)
                
                for user_data in results:
                    parsed_user = self._parse_user_data(user_data)
                    if parsed_user:
                        if parsed_user["type"] == "Organization":
                            organizations.append(parsed_user)
                        else:
                            users.append(parsed_user)
                
                await asyncio.sleep(1)  # Rate limiting
        
        logger.info(f"👥 Found {len(organizations)} organizations and {len(users)} users")
        return {"organizations": organizations[:20], "users": users[:50]}
    
    async def _search_users(self, client: 'httpx.AsyncClient', query: str) -> List[Dict[str, Any]]:
        """Search GitHub users and organizations"""
        users = []
        
        try:
            await self._check_rate_limit(client)
            
            search_url = f"{self.api_base}/search/users"
            params = {
                "q": query,
                "per_page": 30
            }
            
            response = await client.get(search_url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                users = data.get("items", [])
            
        except Exception as e:
            logger.warning(f"User search failed: {e}")
        
        return users
    
    def _parse_user_data(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GitHub user data"""
        try:
            return {
                "login": user_data.get("login"),
                "name": user_data.get("name", ""),
                "type": user_data.get("type", "User"),
                "public_repos": user_data.get("public_repos", 0),
                "followers": user_data.get("followers", 0),
                "following": user_data.get("following", 0),
                "created_at": user_data.get("created_at"),
                "company": user_data.get("company", ""),
                "location": user_data.get("location", ""),
                "email": user_data.get("email", ""),
                "url": user_data.get("html_url")
            }
        except Exception as e:
            logger.warning(f"Failed to parse user data: {e}")
            return None
    
    async def _analyze_repository_contents(self, repositories: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze repository contents for sensitive information"""
        sensitive_files = []
        secrets = []
        
        import httpx
        
        # Sensitive file patterns
        sensitive_patterns = {
            "credentials": [".env", ".env.local", ".env.production", "credentials", "secrets"],
            "config": ["config.json", "config.yaml", "app.config", "web.config"],
            "keys": ["id_rsa", "id_dsa", "private.key", "server.key"],
            "database": ["database.yml", "db.json", "connection.json"],
            "docker": ["Dockerfile", "docker-compose.yml", ".dockerignore"],
            "backup": [".sql", ".dump", "backup", ".bak"]
        }
        
        async with httpx.AsyncClient(timeout=20.0) as client:
            for repo in repositories[:10]:  # Limit analysis
                if self.is_cancelled():
                    break
                
                try:
                    # Get repository file tree
                    file_tree = await self._get_repository_files(client, repo)
                    
                    # Analyze files for sensitive content
                    for file_path in file_tree:
                        file_analysis = self._analyze_file_path(file_path, repo)
                        
                        if file_analysis["is_sensitive"]:
                            sensitive_files.append({
                                "repository": repo["full_name"],
                                "file_path": file_path,
                                "category": file_analysis["category"],
                                "risk_level": file_analysis["risk_level"],
                                "url": f"https://github.com/{repo['full_name']}/blob/main/{file_path}"
                            })
                        
                        # Check for secrets in specific files
                        if file_analysis["check_content"]:
                            file_secrets = await self._analyze_file_content(client, repo, file_path)
                            secrets.extend(file_secrets)
                
                except Exception as e:
                    logger.warning(f"Failed to analyze repository {repo.get('full_name')}: {e}")
                
                await asyncio.sleep(0.5)  # Rate limiting
        
        return {"sensitive_files": sensitive_files, "secrets": secrets}
    
    async def _get_repository_files(self, client: 'httpx.AsyncClient', repo: Dict[str, Any]) -> List[str]:
        """Get list of files in repository"""
        files = []
        
        try:
            await self._check_rate_limit(client)
            
            # Get repository tree
            tree_url = f"{self.api_base}/repos/{repo['full_name']}/git/trees/main?recursive=1"
            response = await client.get(tree_url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get("tree", []):
                    if item.get("type") == "blob":  # File (not directory)
                        files.append(item.get("path", ""))
        
        except Exception as e:
            logger.warning(f"Failed to get file tree for {repo.get('full_name')}: {e}")
        
        return files
    
    def _analyze_file_path(self, file_path: str, repo: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file path for sensitivity indicators"""
        file_lower = file_path.lower()
        
        # High-risk file patterns
        high_risk_patterns = [".env", "secret", "credential", "private", ".key", ".pem", ".p12"]
        medium_risk_patterns = ["config", "docker", ".sql", ".dump", "backup"]
        
        analysis = {
            "is_sensitive": False,
            "category": "unknown",
            "risk_level": "low",
            "check_content": False
        }
        
        # Check for high-risk patterns
        for pattern in high_risk_patterns:
            if pattern in file_lower:
                analysis["is_sensitive"] = True
                analysis["category"] = "credentials" if pattern in [".env", "secret", "credential"] else "keys"
                analysis["risk_level"] = "high"
                analysis["check_content"] = True
                return analysis
        
        # Check for medium-risk patterns
        for pattern in medium_risk_patterns:
            if pattern in file_lower:
                analysis["is_sensitive"] = True
                analysis["category"] = "configuration"
                analysis["risk_level"] = "medium"
                analysis["check_content"] = pattern in ["config", ".sql"]
                return analysis
        
        # Check for code files that might contain secrets
        code_extensions = [".js", ".py", ".php", ".java", ".go", ".rb", ".cs"]
        if any(file_lower.endswith(ext) for ext in code_extensions):
            analysis["check_content"] = True
        
        return analysis
    
    async def _analyze_file_content(self, client: 'httpx.AsyncClient', repo: Dict[str, Any], file_path: str) -> List[Dict[str, Any]]:
        """Analyze file content for secrets"""
        secrets = []
        
        try:
            await self._check_rate_limit(client)
            
            # Get file content
            content_url = f"{self.api_base}/repos/{repo['full_name']}/contents/{file_path}"
            response = await client.get(content_url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                
                # Decode base64 content
                if data.get("encoding") == "base64":
                    try:
                        content = base64.b64decode(data["content"]).decode('utf-8')
                        
                        # Analyze content for secrets
                        file_secrets = self._detect_secrets_in_content(content, repo, file_path)
                        secrets.extend(file_secrets)
                        
                    except Exception as e:
                        logger.warning(f"Failed to decode file content: {e}")
        
        except Exception as e:
            logger.warning(f"Failed to get file content: {e}")
        
        return secrets
    
    def _detect_secrets_in_content(self, content: str, repo: Dict[str, Any], file_path: str) -> List[Dict[str, Any]]:
        """Detect secrets in file content"""
        secrets = []
        
        # Secret patterns
        import re
        
        secret_patterns = [
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[\'\"]([\w\-]{20,})[\'\"]\s', "API Key"),
            (r'(?i)(secret|token)\s*[:=]\s*[\'\"]([\w\-]{16,})[\'\"]\s', "Secret/Token"),
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'\"]([\w\-@$!%*?&]{8,})[\'\"]\s', "Password"),
            (r'github[_-]?token[\'\"]\s*[:=]\s*[\'\"](ghp_[a-zA-Z0-9]{36})[\'\"]\s', "GitHub Token"),
            (r'-----BEGIN [A-Z]+ PRIVATE KEY-----', "Private Key"),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                secret_value = match.group(2) if len(match.groups()) > 1 else match.group(0)
                
                secrets.append({
                    "type": secret_type,
                    "value": secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
                    "repository": repo["full_name"],
                    "file_path": file_path,
                    "line_content": match.group(0),
                    "severity": "critical" if secret_type in ["Private Key", "GitHub Token"] else "high",
                    "url": f"https://github.com/{repo['full_name']}/blob/main/{file_path}"
                })
        
        return secrets
    
    async def _detect_security_issues(self, repositories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect security issues in repositories"""
        security_issues = []
        
        for repo in repositories:
            # Analyze repository metadata for security issues
            issues = []
            
            # Check for outdated repositories
            if repo.get("pushed_at"):
                try:
                    pushed_date = datetime.fromisoformat(repo["pushed_at"].replace('Z', '+00:00'))
                    if datetime.utcnow().replace(tzinfo=pushed_date.tzinfo) - pushed_date > timedelta(days=365):
                        issues.append({
                            "type": "Outdated Repository",
                            "severity": "medium",
                            "description": "Repository hasn't been updated in over a year",
                            "recommendation": "Review and archive if no longer maintained"
                        })
                except Exception:
                    pass
            
            # Check for public repositories with sensitive names
            sensitive_keywords = ["internal", "private", "secret", "credential", "backup", "dump"]
            repo_name_lower = repo.get("name", "").lower()
            
            if any(keyword in repo_name_lower for keyword in sensitive_keywords):
                issues.append({
                    "type": "Potentially Sensitive Repository",
                    "severity": "medium",
                    "description": "Repository name suggests it might contain sensitive information",
                    "recommendation": "Review repository content and consider making private"
                })
            
            # Check for high-profile repositories (many stars/forks)
            if repo.get("stars", 0) > 100 or repo.get("forks", 0) > 50:
                issues.append({
                    "type": "High-Profile Repository",
                    "severity": "info",
                    "description": "Repository has significant community attention",
                    "recommendation": "Ensure security practices are followed due to visibility"
                })
            
            if issues:
                security_issues.append({
                    "repository": repo["full_name"],
                    "url": repo.get("url"),
                    "issues": issues
                })
        
        return security_issues
    
    async def _check_rate_limit(self, client: 'httpx.AsyncClient'):
        """Check and handle GitHub API rate limiting"""
        if self.rate_limit_remaining <= 10:
            wait_time = (self.rate_limit_reset - datetime.utcnow()).total_seconds()
            if wait_time > 0:
                logger.warning(f"⏳ Rate limit low, waiting {wait_time:.0f} seconds")
                await asyncio.sleep(min(wait_time, 60))
    
    def _generate_intelligence_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligence summary"""
        repositories = results.get("repositories", [])
        organizations = results.get("organizations", [])
        users = results.get("users", [])
        sensitive_files = results.get("sensitive_files", [])
        secrets = results.get("secrets_exposed", [])
        
        return {
            "total_repositories": len(repositories),
            "total_organizations": len(organizations),
            "total_users": len(users),
            "sensitive_files_found": len(sensitive_files),
            "secrets_exposed": len(secrets),
            "high_risk_repositories": len([r for r in repositories if r.get("is_private") == False]),
            "recently_active_repos": len([r for r in repositories if self._is_recently_active(r)]),
            "popular_repositories": len([r for r in repositories if r.get("stars", 0) > 10]),
            "risk_assessment": self._assess_overall_risk(results)
        }
    
    def _is_recently_active(self, repo: Dict[str, Any]) -> bool:
        """Check if repository is recently active"""
        if not repo.get("pushed_at"):
            return False
        
        try:
            pushed_date = datetime.fromisoformat(repo["pushed_at"].replace('Z', '+00:00'))
            return (datetime.utcnow().replace(tzinfo=pushed_date.tzinfo) - pushed_date).days < 30
        except:
            return False
    
    def _assess_overall_risk(self, results: Dict[str, Any]) -> str:
        """Assess overall security risk level"""
        risk_score = 0
        
        # Count risk factors
        secrets = len(results.get("secrets_exposed", []))
        sensitive_files = len(results.get("sensitive_files", []))
        public_repos = len([r for r in results.get("repositories", []) if not r.get("is_private")])
        
        # Calculate risk
        risk_score += secrets * 3  # Secrets are high risk
        risk_score += sensitive_files * 2  # Sensitive files are medium risk
        risk_score += public_repos * 1  # Public repos are low risk
        
        if risk_score >= 20:
            return "Critical"
        elif risk_score >= 10:
            return "High"
        elif risk_score >= 5:
            return "Medium"
        else:
            return "Low"
    
    def _generate_metadata(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate metadata for results"""
        repositories = results.get("repositories", [])
        
        # Language distribution
        languages = {}
        for repo in repositories:
            lang = repo.get("language", "Unknown")
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
        
        # Repository sizes
        sizes = [repo.get("size", 0) for repo in repositories]
        avg_size = sum(sizes) / max(len(sizes), 1)
        
        return {
            "language_distribution": dict(sorted(languages.items(), key=lambda x: x[1], reverse=True)[:10]),
            "average_repository_size_kb": round(avg_size, 2),
            "total_stars": sum(repo.get("stars", 0) for repo in repositories),
            "total_forks": sum(repo.get("forks", 0) for repo in repositories),
            "scan_timestamp": datetime.utcnow().isoformat(),
            "api_rate_limit_used": 5000 - self.rate_limit_remaining if self.api_token else "N/A"
        }
