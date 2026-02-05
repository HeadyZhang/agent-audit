"""MCP configuration scanner for static analysis of MCP server configs."""

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field

import yaml

from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class MCPSecurityFinding:
    """Security finding from MCP config analysis."""
    rule_id: str
    server_name: str
    finding_type: str
    description: str
    severity: str
    line: int = 1
    snippet: str = ""
    owasp_id: Optional[str] = None


@dataclass
class MCPServerConfig:
    """Parsed MCP server configuration."""
    name: str
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    url: Optional[str] = None
    env: Dict[str, str] = field(default_factory=dict)
    transport: Optional[str] = None  # stdio, sse, streamable-http
    verified: bool = False
    _line: int = 1  # Source line for error reporting
    _source_file: str = ""


@dataclass
class MCPConfigScanResult(ScanResult):
    """Result of MCP configuration scanning."""
    servers: List[MCPServerConfig] = field(default_factory=list)
    config_type: str = "unknown"  # claude_desktop, docker_mcp, standard
    security_findings: List[MCPSecurityFinding] = field(default_factory=list)


class MCPConfigScanner(BaseScanner):
    """
    Static scanner for MCP configuration files.

    Supports:
    - Claude Desktop config (mcpServers)
    - Docker MCP config (gateway.servers)
    - Standard MCP config (servers[])
    """

    name = "MCP Config Scanner"

    # Known config file names (extended for v0.3.0)
    CONFIG_FILENAMES = [
        'claude_desktop_config.json',
        'mcp.json',
        'mcp-config.json',
        'mcp.yaml',
        'mcp.yml',
        'mcp-config.yaml',
        'mcp-config.yml',
        'docker-mcp.json',
        'docker-mcp.yaml',
        'cline_mcp_settings.json',
    ]

    # Additional file patterns to check
    CONFIG_PATTERNS = [
        '*.mcp.json',
        '.cursor/mcp.json',
    ]

    # Trusted MCP server sources
    TRUSTED_SOURCES = [
        'docker.io/mcp-catalog/',
        'ghcr.io/anthropics/',
        'ghcr.io/modelcontextprotocol/',
        '@modelcontextprotocol/',
    ]

    # Dangerous root/home paths for AGENT-029
    DANGEROUS_PATHS: List[str] = [
        '/', '/home', '/etc', '/usr', '/var', '/root',
        '~', '$HOME', '%USERPROFILE%', '%HOMEPATH%',
        'C:\\', 'C:/', 'D:\\', 'D:/',
    ]

    # Sensitive env key patterns for AGENT-031
    SENSITIVE_ENV_PATTERN = re.compile(
        r'(?i)(key|secret|token|password|credential|auth|private)',
        re.IGNORECASE
    )

    # Safe env key names (not secrets)
    SAFE_ENV_KEYS = {
        'PATH', 'NODE_ENV', 'LOG_LEVEL', 'DEBUG', 'VERBOSE',
        'HOME', 'USER', 'SHELL', 'TERM', 'LANG', 'LC_ALL',
        'TZ', 'PYTHONPATH', 'NODE_PATH',
    }

    # Placeholder values that indicate misconfiguration
    PLACEHOLDER_PATTERNS = [
        r'your[-_]?api[-_]?key[-_]?here',
        r'<your[-_]?key>',
        r'xxx+',
        r'TODO',
        r'CHANGEME',
        r'insert[-_]?here',
        r'replace[-_]?me',
    ]

    def __init__(self, config_paths: Optional[List[Path]] = None):
        """
        Initialize the MCP config scanner.

        Args:
            config_paths: Specific config files to scan. If None,
                         auto-discovers config files.
        """
        self.config_paths = config_paths

    def scan(self, path: Path) -> List[MCPConfigScanResult]:
        """
        Scan for MCP configuration files.

        Args:
            path: Directory or file to scan

        Returns:
            List of scan results with security findings
        """
        results = []
        config_files = self._find_config_files(path)

        for config_file in config_files:
            result = self._scan_config_file(config_file)
            if result:
                # Perform security analysis
                security_findings = self.analyze_security(result)
                result.security_findings = security_findings
                results.append(result)

        return results

    def _find_config_files(self, path: Path) -> List[Path]:
        """
        Find MCP configuration files.

        KNOWN-003 FIX: Now scans all JSON/YAML files in directory to detect
        MCP configs with mcpServers/servers/gateway keys, not just known filenames.
        """
        if self.config_paths:
            return [p for p in self.config_paths if p.exists()]

        if path.is_file():
            if path.name in self.CONFIG_FILENAMES or self._looks_like_mcp_config(path):
                return [path]
            return []

        config_files: List[Path] = []
        seen_paths: Set[str] = set()

        # Check for known config file names first (highest priority)
        for filename in self.CONFIG_FILENAMES:
            config_path = path / filename
            if config_path.exists():
                config_files.append(config_path)
                seen_paths.add(str(config_path.resolve()))

        # Check .claude directory
        claude_dir = path / '.claude'
        if claude_dir.exists():
            for json_file in claude_dir.glob('*.json'):
                resolved = str(json_file.resolve())
                if resolved not in seen_paths and self._looks_like_mcp_config(json_file):
                    config_files.append(json_file)
                    seen_paths.add(resolved)

        # Check .cursor directory (common IDE config location)
        cursor_dir = path / '.cursor'
        if cursor_dir.exists():
            for json_file in cursor_dir.glob('*.json'):
                resolved = str(json_file.resolve())
                if resolved not in seen_paths and self._looks_like_mcp_config(json_file):
                    config_files.append(json_file)
                    seen_paths.add(resolved)

        # KNOWN-003 FIX: Scan all JSON/YAML files in directory for MCP config patterns
        # This catches configs with non-standard names that contain mcpServers/servers/gateway
        json_yaml_extensions = {'.json', '.yaml', '.yml'}
        for file_path in path.iterdir():
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in json_yaml_extensions:
                continue
            resolved = str(file_path.resolve())
            if resolved in seen_paths:
                continue
            # Check if file contains MCP config indicators
            if self._looks_like_mcp_config(file_path):
                config_files.append(file_path)
                seen_paths.add(resolved)

        return config_files

    def _looks_like_mcp_config(self, file_path: Path) -> bool:
        """Check if a file looks like an MCP config."""
        try:
            content = file_path.read_text(encoding='utf-8')

            if file_path.suffix == '.json':
                data = json.loads(content)
            elif file_path.suffix in {'.yaml', '.yml'}:
                data = yaml.safe_load(content)
            else:
                return False

            if not isinstance(data, dict):
                return False

            # Check for MCP config indicators
            return any(key in data for key in [
                'mcpServers', 'servers', 'gateway'
            ])

        except Exception:
            return False

    def _scan_config_file(self, file_path: Path) -> Optional[MCPConfigScanResult]:
        """Scan a single config file."""
        try:
            content = file_path.read_text(encoding='utf-8')

            if file_path.suffix == '.json':
                data = json.loads(content)
            elif file_path.suffix in {'.yaml', '.yml'}:
                data = yaml.safe_load(content)
            else:
                logger.warning(f"Unsupported config format: {file_path}")
                return None

            if not isinstance(data, dict):
                return None

            # Detect config type and parse
            servers, config_type = self._parse_config(data, str(file_path))

            return MCPConfigScanResult(
                source_file=str(file_path),
                servers=servers,
                config_type=config_type
            )

        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse error in {file_path}: {e}")
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
        except Exception as e:
            logger.warning(f"Error scanning {file_path}: {e}")

        return None

    def _parse_config(
        self,
        data: Dict[str, Any],
        source_file: str
    ) -> tuple[List[MCPServerConfig], str]:
        """Parse MCP config and detect format."""
        servers: List[MCPServerConfig] = []
        config_type = "unknown"

        # Claude Desktop format: { "mcpServers": { "name": { ... } } }
        if 'mcpServers' in data:
            config_type = "claude_desktop"
            mcp_servers = data['mcpServers']
            if isinstance(mcp_servers, dict):
                for name, config in mcp_servers.items():
                    # Skip non-dict values (comments, metadata fields)
                    if not isinstance(config, dict):
                        continue
                    server = self._parse_server_config(name, config, source_file)
                    servers.append(server)

        # Docker MCP format: { "gateway": { "servers": [ ... ] } }
        elif 'gateway' in data and isinstance(data['gateway'], dict):
            config_type = "docker_mcp"
            gateway_servers = data['gateway'].get('servers', [])
            if isinstance(gateway_servers, list):
                for config in gateway_servers:
                    name = config.get('name', config.get('image', 'unknown'))
                    server = self._parse_server_config(name, config, source_file)
                    servers.append(server)

        # Standard MCP format: { "servers": [ ... ] }
        elif 'servers' in data:
            config_type = "standard"
            if isinstance(data['servers'], list):
                for config in data['servers']:
                    if not isinstance(config, dict):
                        continue
                    name = config.get('name', 'unknown')
                    server = self._parse_server_config(name, config, source_file)
                    servers.append(server)
            elif isinstance(data['servers'], dict):
                for name, config in data['servers'].items():
                    # Skip non-dict values (comments, metadata fields)
                    if not isinstance(config, dict):
                        continue
                    server = self._parse_server_config(name, config, source_file)
                    servers.append(server)

        return servers, config_type

    def _parse_server_config(
        self,
        name: str,
        config: Dict[str, Any],
        source_file: str
    ) -> MCPServerConfig:
        """Parse a single server configuration."""
        # Detect transport type
        transport = config.get('transport')
        if not transport:
            url = config.get('url', '')
            if url:
                if 'sse' in url.lower() or url.endswith('/sse'):
                    transport = 'sse'
                elif url.startswith('http://') or url.startswith('https://'):
                    transport = 'streamable-http'
            else:
                transport = 'stdio'

        server = MCPServerConfig(
            name=name,
            command=config.get('command'),
            args=config.get('args', []),
            url=config.get('url'),
            env=config.get('env', {}),
            transport=transport,
            verified=self._is_verified_source(config),
            _source_file=source_file
        )

        return server

    def _is_verified_source(self, config: Dict[str, Any]) -> bool:
        """
        Check if a server configuration is from a trusted source.

        Trusted sources include:
        - Official MCP catalog Docker images
        - Anthropic's GitHub packages
        - ModelContextProtocol npm packages
        """
        # Check URL
        url = config.get('url', '')
        if url and any(url.startswith(src) for src in self.TRUSTED_SOURCES):
            return True

        # Check Docker image
        image = config.get('image', '')
        if image and any(image.startswith(src) for src in self.TRUSTED_SOURCES):
            return True

        # Check npm package in args
        args = config.get('args', [])
        for arg in args:
            if isinstance(arg, str):
                if any(src in arg for src in self.TRUSTED_SOURCES):
                    return True

        return False

    def get_dangerous_env_vars(self, server: MCPServerConfig) -> List[Dict[str, Any]]:
        """
        Find potentially dangerous environment variables.

        Returns list of env vars that may contain credentials.
        """
        dangerous = []
        sensitive_patterns = [
            'KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'CREDENTIAL',
            'API_KEY', 'AUTH', 'PRIVATE'
        ]

        for key, value in server.env.items():
            key_upper = key.upper()
            if any(pattern in key_upper for pattern in sensitive_patterns):
                # Check if it looks like a hardcoded secret
                if isinstance(value, str) and len(value) > 10:
                    if not value.startswith('${') and not value.startswith('$'):
                        dangerous.append({
                            'key': key,
                            'value_preview': value[:10] + '...',
                            'reason': 'Potential hardcoded credential'
                        })

        return dangerous

    def check_filesystem_access(self, server: MCPServerConfig) -> Dict[str, Any]:
        """
        Check for overly permissive filesystem access.

        Returns analysis of filesystem access configuration.
        """
        accessible_paths: List[str] = []
        result: Dict[str, Any] = {
            'has_root_access': False,
            'has_home_access': False,
            'accessible_paths': accessible_paths,
            'risk_level': 'low'
        }

        # Check args for path access
        for arg in server.args:
            if isinstance(arg, str):
                if arg == '/':
                    result['has_root_access'] = True
                    result['risk_level'] = 'critical'
                elif arg.startswith('/home') or arg == '~' or arg.startswith('$HOME'):
                    result['has_home_access'] = True
                    result['risk_level'] = 'high' if result['risk_level'] != 'critical' else 'critical'
                elif arg.startswith('/'):
                    accessible_paths.append(arg)

        return result

    # =========================================================================
    # v0.3.0 Security Detection Methods (AGENT-029 through AGENT-033)
    # =========================================================================

    def analyze_security(
        self,
        result: MCPConfigScanResult
    ) -> List[MCPSecurityFinding]:
        """
        Perform comprehensive security analysis on MCP config.

        Returns list of security findings for all servers in the config.
        """
        findings: List[MCPSecurityFinding] = []

        # v0.3.2: AGENT-042 - Excessive MCP servers (ASI-03)
        excessive_findings = self._check_excessive_servers(result)
        findings.extend(excessive_findings)

        for server in result.servers:
            # AGENT-029: Overly broad filesystem access
            fs_findings = self._check_overly_broad_filesystem(server)
            findings.extend(fs_findings)

            # AGENT-030: Unverified server source (npx/uvx without version)
            source_findings = self._check_unverified_server_source(server)
            findings.extend(source_findings)

            # AGENT-031: Sensitive env exposure
            env_findings = self._check_sensitive_env_exposure(server)
            findings.extend(env_findings)

            # AGENT-032: stdio without sandbox
            sandbox_findings = self._check_stdio_no_sandbox(server)
            findings.extend(sandbox_findings)

            # AGENT-033: Missing auth for SSE/HTTP
            auth_findings = self._check_missing_auth(server)
            findings.extend(auth_findings)

        return findings

    def _check_overly_broad_filesystem(
        self,
        server: MCPServerConfig
    ) -> List[MCPSecurityFinding]:
        """
        AGENT-029: Check for overly broad filesystem access.

        Triggers when:
        - args contain root path (/), home path (~, /home, $HOME)
        - args contain wildcards (* or **)
        - args contain path traversal (..)
        - filesystem server has no path restriction
        """
        findings: List[MCPSecurityFinding] = []

        # Check if this looks like a filesystem server
        is_filesystem_server = (
            'filesystem' in server.name.lower() or
            any('filesystem' in str(arg).lower() for arg in server.args)
        )

        for arg in server.args:
            if not isinstance(arg, str):
                continue

            # Check for dangerous root/home paths
            for dangerous_path in self.DANGEROUS_PATHS:
                if arg == dangerous_path or arg.rstrip('/\\') == dangerous_path.rstrip('/\\'):
                    findings.append(MCPSecurityFinding(
                        rule_id="AGENT-029",
                        server_name=server.name,
                        finding_type="mcp_overly_broad_filesystem",
                        description=(
                            f"MCP server '{server.name}' has access to '{arg}' "
                            "which grants overly broad filesystem permissions"
                        ),
                        severity="high",
                        line=server._line,
                        snippet=f"args: [..., \"{arg}\", ...]",
                        owasp_id="ASI-02"
                    ))
                    break

            # Check for wildcards
            if '*' in arg or '**' in arg:
                findings.append(MCPSecurityFinding(
                    rule_id="AGENT-029",
                    server_name=server.name,
                    finding_type="mcp_overly_broad_filesystem",
                    description=(
                        f"MCP server '{server.name}' uses wildcard path '{arg}' "
                        "which may grant unintended access"
                    ),
                    severity="high",
                    line=server._line,
                    snippet=f"args: [..., \"{arg}\", ...]",
                    owasp_id="ASI-02"
                ))

            # Check for path traversal
            if '..' in arg:
                findings.append(MCPSecurityFinding(
                    rule_id="AGENT-029",
                    server_name=server.name,
                    finding_type="mcp_overly_broad_filesystem",
                    description=(
                        f"MCP server '{server.name}' uses path traversal '{arg}' "
                        "which may escape intended directory"
                    ),
                    severity="high",
                    line=server._line,
                    snippet=f"args: [..., \"{arg}\", ...]",
                    owasp_id="ASI-02"
                ))

        # Check if filesystem server has NO path restriction at all
        if is_filesystem_server:
            # Skip npx package name arguments
            path_args = [
                arg for arg in server.args
                if isinstance(arg, str) and
                not arg.startswith('-') and
                not arg.startswith('@') and
                arg not in ('npx', 'uvx', 'node', 'python')
            ]
            if not path_args:
                findings.append(MCPSecurityFinding(
                    rule_id="AGENT-029",
                    server_name=server.name,
                    finding_type="mcp_overly_broad_filesystem",
                    description=(
                        f"Filesystem server '{server.name}' has no explicit "
                        "path restriction configured"
                    ),
                    severity="medium",
                    line=server._line,
                    snippet=f"args: {server.args}",
                    owasp_id="ASI-02"
                ))

        return findings

    def _check_unverified_server_source(
        self,
        server: MCPServerConfig
    ) -> List[MCPSecurityFinding]:
        """
        AGENT-030: Check for unverified/unpinned server source.

        Triggers when:
        - npx/npx -y with package name lacking @x.y.z version
        - uvx with package name lacking version
        - node executing remote URL
        - http:// URL (non-https) for SSE/HTTP transport
        """
        findings: List[MCPSecurityFinding] = []
        command = server.command or ''
        args = server.args or []

        # Check for npx without version pinning
        if command in ('npx', 'node') or (args and args[0] == 'npx'):
            # Find the package name in args
            for i, arg in enumerate(args):
                if not isinstance(arg, str):
                    continue
                # Skip flags
                if arg.startswith('-'):
                    continue
                # Skip npx itself if it's in args
                if arg == 'npx':
                    continue

                # Check if this looks like an npm package name
                if arg.startswith('@') or (
                    not arg.startswith('/') and
                    not arg.startswith('.') and
                    '/' not in arg[:20] if len(arg) > 20 else '/' not in arg
                ):
                    # Check for version pinning
                    has_version = bool(re.search(r'@\d+\.\d+', arg))

                    # Allow official modelcontextprotocol packages even without version
                    is_official = '@modelcontextprotocol/' in arg

                    if not has_version and not is_official:
                        findings.append(MCPSecurityFinding(
                            rule_id="AGENT-030",
                            server_name=server.name,
                            finding_type="mcp_unverified_server_source",
                            description=(
                                f"MCP server '{server.name}' uses unpinned package "
                                f"'{arg}'. Pin to specific version with @x.y.z"
                            ),
                            severity="critical",
                            line=server._line,
                            snippet=f"command: {command}, args: {args}",
                            owasp_id="ASI-04"
                        ))
                    break

        # Check for uvx without version
        if command == 'uvx':
            for arg in args:
                if not isinstance(arg, str):
                    continue
                if arg.startswith('-'):
                    continue
                # Check if it's a package name without version
                if not re.search(r'[=@]\d+\.\d+', arg):
                    findings.append(MCPSecurityFinding(
                        rule_id="AGENT-030",
                        server_name=server.name,
                        finding_type="mcp_unverified_server_source",
                        description=(
                            f"MCP server '{server.name}' uses unpinned uvx package "
                            f"'{arg}'. Pin to specific version"
                        ),
                        severity="critical",
                        line=server._line,
                        snippet=f"command: uvx, args: {args}",
                        owasp_id="ASI-04"
                    ))
                break

        # Check for http:// URL (non-HTTPS)
        url = server.url or ''
        if url.startswith('http://'):
            findings.append(MCPSecurityFinding(
                rule_id="AGENT-030",
                server_name=server.name,
                finding_type="mcp_unverified_server_source",
                description=(
                    f"MCP server '{server.name}' uses unencrypted HTTP URL: {url}. "
                    "Use HTTPS for secure communication"
                ),
                severity="critical",
                line=server._line,
                snippet=f"url: {url}",
                owasp_id="ASI-04"
            ))

        return findings

    def _check_sensitive_env_exposure(
        self,
        server: MCPServerConfig
    ) -> List[MCPSecurityFinding]:
        """
        AGENT-031: Check for sensitive environment variable exposure.

        Triggers when:
        - env key matches sensitive pattern AND value is plaintext (not ${VAR})
        - env value matches placeholder patterns (your-api-key-here, xxx, TODO)
        """
        findings: List[MCPSecurityFinding] = []

        for key, value in server.env.items():
            if not isinstance(value, str):
                continue

            # Skip safe keys
            if key.upper() in self.SAFE_ENV_KEYS:
                continue

            # Check if key looks sensitive
            is_sensitive_key = bool(self.SENSITIVE_ENV_PATTERN.search(key))

            if is_sensitive_key:
                # Check if value is hardcoded (not a variable reference)
                is_env_reference = (
                    value.startswith('${') or
                    value.startswith('$') or
                    value.startswith('%') and value.endswith('%')
                )

                if not is_env_reference and len(value) > 0:
                    # Check for placeholder patterns
                    is_placeholder = any(
                        re.search(pattern, value, re.IGNORECASE)
                        for pattern in self.PLACEHOLDER_PATTERNS
                    )

                    if is_placeholder:
                        findings.append(MCPSecurityFinding(
                            rule_id="AGENT-031",
                            server_name=server.name,
                            finding_type="mcp_sensitive_env_exposure",
                            description=(
                                f"MCP server '{server.name}' has placeholder value "
                                f"for sensitive key '{key}'. Replace with actual "
                                "secret or environment variable reference"
                            ),
                            severity="medium",
                            line=server._line,
                            snippet=f"env: {{\"{key}\": \"<placeholder>\"}}",
                            owasp_id="ASI-05"
                        ))
                    else:
                        # It's a hardcoded secret
                        masked_value = value[:4] + '***' if len(value) > 4 else '***'
                        findings.append(MCPSecurityFinding(
                            rule_id="AGENT-031",
                            server_name=server.name,
                            finding_type="mcp_sensitive_env_exposure",
                            description=(
                                f"MCP server '{server.name}' has hardcoded value "
                                f"for sensitive key '{key}'. Use environment "
                                "variable reference like ${" + key + "} instead"
                            ),
                            severity="high",
                            line=server._line,
                            snippet=f"env: {{\"{key}\": \"{masked_value}\"}}",
                            owasp_id="ASI-05"
                        ))

        return findings

    def _check_stdio_no_sandbox(
        self,
        server: MCPServerConfig
    ) -> List[MCPSecurityFinding]:
        """
        AGENT-032: Check for stdio transport without sandbox isolation.

        Triggers when:
        - transport=stdio AND no evidence of container/sandbox wrapping
        - Excludes official @modelcontextprotocol packages (considered trusted)
        """
        findings: List[MCPSecurityFinding] = []

        if server.transport != 'stdio':
            return findings

        # Look for sandbox evidence in command or args
        command = (server.command or '').lower()
        args_str = ' '.join(str(arg) for arg in server.args).lower()
        all_config = f"{command} {args_str}"

        sandbox_indicators = [
            'docker', 'podman', 'container', 'sandbox',
            'nsjail', 'firejail', 'bubblewrap', 'bwrap',
            '--read-only', 'seccomp', 'apparmor',
        ]

        has_sandbox = any(indicator in all_config for indicator in sandbox_indicators)

        # Skip if using official MCP packages (trusted)
        is_official_mcp = '@modelcontextprotocol/' in args_str

        if not has_sandbox and not is_official_mcp:
            # Only flag if the server runs executable code or has broad capabilities
            risky_indicators = [
                'python', 'shell', 'bash', 'exec', 'eval',
                'database', 'sql', 'code', 'repl', 'interpreter',
            ]
            # 'node' alone is not risky if it's running a specific server.js
            # Only flag 'node' with risky keywords
            is_risky = any(
                indicator in all_config for indicator in risky_indicators
            )

            # Additional check: flag custom python/node servers without isolation
            if command in ('python', 'python3') or (
                command == 'node' and any(
                    kw in all_config for kw in ['shell', 'exec', 'eval', 'code', 'repl']
                )
            ):
                is_risky = True

            if is_risky:
                findings.append(MCPSecurityFinding(
                    rule_id="AGENT-032",
                    server_name=server.name,
                    finding_type="mcp_stdio_no_sandbox",
                    description=(
                        f"MCP server '{server.name}' uses stdio transport without "
                        "apparent sandbox isolation. Consider running in a container"
                    ),
                    severity="medium",
                    line=server._line,
                    snippet=f"command: {server.command}, transport: stdio",
                    owasp_id="ASI-02"
                ))

        return findings

    def _check_missing_auth(
        self,
        server: MCPServerConfig
    ) -> List[MCPSecurityFinding]:
        """
        AGENT-033: Check for missing authentication on SSE/HTTP transport.

        Triggers when:
        - transport is sse or streamable-http
        - config has no auth/token/apiKey/headers.Authorization field
        """
        findings: List[MCPSecurityFinding] = []

        # Only check SSE or HTTP transports
        if server.transport not in ('sse', 'streamable-http'):
            return findings

        # Look for auth configuration evidence
        # Check in env for auth-related keys
        auth_env_keys = [
            'auth', 'token', 'api_key', 'apikey', 'authorization',
            'bearer', 'secret', 'credential', 'password',
        ]
        has_auth_env = any(
            any(auth_key in key.lower() for auth_key in auth_env_keys)
            for key in server.env.keys()
        )

        # Also check URL for basic auth (user:pass@host)
        url = server.url or ''
        has_url_auth = '@' in url and '://' in url

        if not has_auth_env and not has_url_auth:
            findings.append(MCPSecurityFinding(
                rule_id="AGENT-033",
                server_name=server.name,
                finding_type="mcp_missing_auth",
                description=(
                    f"MCP server '{server.name}' uses {server.transport} transport "
                    "without authentication configuration. Add auth token or API key"
                ),
                severity="high",
                line=server._line,
                snippet=f"url: {url}, transport: {server.transport}",
                owasp_id="ASI-09"
            ))

        return findings

    def _check_excessive_servers(
        self,
        result: MCPConfigScanResult
    ) -> List[MCPSecurityFinding]:
        """
        AGENT-042 (v0.3.2): Detect excessive number of MCP servers.

        ASI-03 (Excessive Agency) - Too many servers configured indicates
        the agent has excessive capability surface area.

        Threshold: > 10 servers triggers a finding.
        """
        findings: List[MCPSecurityFinding] = []

        server_count = len(result.servers)
        threshold = 10

        if server_count > threshold:
            # Get first server's line for reporting
            first_line = result.servers[0]._line if result.servers else 1
            server_names = [s.name for s in result.servers[:5]]
            snippet = f"Servers: {', '.join(server_names)}... ({server_count} total)"

            findings.append(MCPSecurityFinding(
                rule_id="AGENT-042",
                server_name="_global_",
                finding_type="mcp_excessive_servers",
                description=(
                    f"MCP configuration has {server_count} servers (threshold: {threshold}). "
                    "This violates the principle of least privilege (ASI-03). "
                    "Consider reducing the number of enabled servers to limit the agent's capability surface."
                ),
                severity="medium",
                line=first_line,
                snippet=snippet,
                owasp_id="ASI-03"
            ))

        return findings
