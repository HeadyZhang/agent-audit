"""Scan command implementation."""

from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console

from agent_audit.models.finding import Finding, deduplicate_findings
from agent_audit.models.risk import Severity
from agent_audit.rules.engine import RuleEngine

from agent_audit.scanners.python_scanner import PythonScanner
from agent_audit.scanners.mcp_config_scanner import MCPConfigScanner
from agent_audit.scanners.secret_scanner import SecretScanner
from agent_audit.scanners.privilege_scanner import PrivilegeScanner
from agent_audit.scanners.skill_meta_scanner import SkillMetaScanner, SkillMetaFinding
from agent_audit.scanners.skill_body_scanner import SkillBodyScanner, SkillBodyFinding
from agent_audit.config.ignore import (
    IgnoreManager, load_baseline, filter_by_baseline, save_baseline
)
from agent_audit.cli.formatters.terminal import format_scan_results

console = Console()


def run_scan(
    path: Path,
    output_format: str,
    output_path: Optional[Path],
    min_severity: str,
    additional_rules: List[str],
    fail_on_severity: str,
    baseline_path: Optional[Path] = None,
    save_baseline_path: Optional[Path] = None,
    rules_dir: Optional[Path] = None,
    verbose: bool = False,
    quiet: bool = False,
    min_tier: Optional[str] = None,
    no_color: bool = False,
    fail_on_new: bool = False,
    profile: Optional[str] = None
) -> int:
    """
    Run the security scan.

    Returns exit code: 0 for success, 1 for findings at fail_on level.
    """
    # Initialize ignore manager first to get exclude patterns
    ignore_manager = IgnoreManager()
    config_loaded = ignore_manager.load(path)

    if verbose and config_loaded and output_format == "terminal":
        console.print(f"[dim]Loaded config from: {ignore_manager._loaded_from}[/dim]")

    # Get exclude patterns from config
    exclude_patterns = ignore_manager.get_exclude_patterns()

    # Initialize scanners with exclude patterns
    python_scanner = PythonScanner(exclude_patterns=exclude_patterns)
    mcp_scanner = MCPConfigScanner()
    secret_scanner = SecretScanner(exclude_paths=exclude_patterns)
    privilege_scanner = PrivilegeScanner(exclude_patterns=exclude_patterns)

    # Initialize rule engine
    rule_engine = RuleEngine()

    # Find rules directory - check multiple possible locations
    # scan.py is at agent_audit/cli/commands/scan.py
    # Rules are at agent_audit/rules/builtin/
    # So we need 3 parents: commands -> cli -> agent_audit
    possible_rules_dirs = [
        # Inside the package (installed via pip/wheel)
        Path(__file__).parent.parent.parent / "rules" / "builtin",
        # Monorepo rules dir (development mode)
        Path(__file__).resolve().parent.parent.parent.parent.parent.parent.parent / "rules" / "builtin",
    ]

    for builtin_dir in possible_rules_dirs:
        if builtin_dir.exists():
            rule_engine.add_builtin_rules_dir(builtin_dir)
            break

    # Load custom rules if --rules-dir is specified
    custom_rules_dirs: Optional[List[Path]] = None
    if rules_dir and rules_dir.exists():
        custom_rules_dirs = [rules_dir]
        if not quiet and output_format == "terminal":
            console.print(f"[dim]Loading custom rules from: {rules_dir}[/dim]")

    rule_engine.load_rules(additional_dirs=custom_rules_dirs)

    # Collect all findings
    all_findings: List[Finding] = []
    scanned_files = 0

    # Run Python scanner
    if not quiet and output_format == "terminal":
        console.print("[dim]Scanning Python files...[/dim]")

    python_results = python_scanner.scan(path)
    for py_result in python_results:
        scanned_files += 1

        # v0.8.0: Read source early for infrastructure detection
        source = None
        try:
            source = Path(py_result.source_file).read_text(encoding='utf-8')
        except Exception:
            pass

        # Generate findings from dangerous patterns
        # v0.8.0: Pass source_code for infrastructure context detection
        findings = rule_engine.evaluate_dangerous_patterns(
            py_result.dangerous_patterns,
            py_result.source_file,
            source_code=source
        )
        all_findings.extend(findings)

        # Note: Credential detection is handled by secret_scanner (with semantic analysis)
        # to avoid duplicate findings. Don't call rule_engine.evaluate_credentials() here.

        # Evaluate tool permissions
        if py_result.tools:
            perm_findings = rule_engine.evaluate_permission_scope(
                py_result.tools,
                py_result.source_file
            )
            all_findings.extend(perm_findings)

    # Run MCP config scanner
    if not quiet and output_format == "terminal":
        console.print("[dim]Scanning MCP configurations...[/dim]")

    mcp_results = mcp_scanner.scan(path)
    for mcp_result in mcp_results:
        scanned_files += 1

        # Convert server configs to dicts for rule engine
        server_dicts = []
        for server in mcp_result.servers:
            server_dict = {
                'name': server.name,
                'url': server.url,
                'command': server.command,
                'args': server.args,
                'env': server.env,
                'verified': server.verified,
                '_line': server._line,
            }
            server_dicts.append(server_dict)

        mcp_findings = rule_engine.evaluate_mcp_config(server_dicts, mcp_result.source_file)
        all_findings.extend(mcp_findings)

        # v0.3.0: Process security findings from enhanced MCP scanner
        for sec_finding in mcp_result.security_findings:
            from agent_audit.models.risk import Location, Category
            from agent_audit.models.finding import Remediation

            # Map severity string to Severity enum
            severity_map = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
            }
            severity = severity_map.get(sec_finding.severity, Severity.MEDIUM)

            # Map finding type to Category
            category_map = {
                'mcp_overly_broad_filesystem': Category.TOOL_MISUSE,
                'mcp_unverified_server_source': Category.SUPPLY_CHAIN_AGENTIC,
                'mcp_sensitive_env_exposure': Category.CREDENTIAL_EXPOSURE,
                'mcp_stdio_no_sandbox': Category.TOOL_MISUSE,
                'mcp_missing_auth': Category.TRUST_EXPLOITATION,
                # v0.17.0: MCP Security Enhancement
                'mcp_tool_shadowing_exact': Category.SUPPLY_CHAIN_AGENTIC,
                'mcp_tool_shadowing_similar': Category.SUPPLY_CHAIN_AGENTIC,
                'mcp_tool_description_poisoning': Category.GOAL_HIJACK,
                'mcp_tool_name_poisoning': Category.GOAL_HIJACK,
                'mcp_tool_arg_poisoning': Category.GOAL_HIJACK,
                'mcp_tool_drift_added': Category.SUPPLY_CHAIN_AGENTIC,
                'mcp_tool_drift_modified': Category.SUPPLY_CHAIN_AGENTIC,
                'mcp_tool_drift_removed': Category.SUPPLY_CHAIN_AGENTIC,
            }
            category = category_map.get(sec_finding.finding_type, Category.SUPPLY_CHAIN)

            finding = Finding(
                rule_id=sec_finding.rule_id,
                title=sec_finding.finding_type.replace('_', ' ').title(),
                description=sec_finding.description,
                severity=severity,
                category=category,
                location=Location(
                    file_path=mcp_result.source_file,
                    start_line=sec_finding.line,
                    end_line=sec_finding.line,
                    snippet=sec_finding.snippet
                ),
                owasp_id=sec_finding.owasp_id,
                remediation=Remediation(
                    description=f"Review and secure the MCP server configuration for '{sec_finding.server_name}'"
                )
            )
            all_findings.append(finding)

    # Run secret scanner
    if not quiet and output_format == "terminal":
        console.print("[dim]Scanning for secrets...[/dim]")

    secret_results = secret_scanner.scan(path)
    for secret_result in secret_results:
        for secret in secret_result.secrets:
            from agent_audit.models.risk import Location, Category
            from agent_audit.models.finding import Remediation, confidence_to_tier

            # v0.5.1: Use semantic analysis results for confidence and tier
            confidence = secret.confidence if hasattr(secret, 'confidence') else 1.0
            tier = secret.tier if hasattr(secret, 'tier') else confidence_to_tier(confidence)

            finding = Finding(
                rule_id="AGENT-004",
                title="Hardcoded Credentials",
                description=f"Found {secret.pattern_name}",
                severity=Severity.CRITICAL if secret.severity == "critical" else
                         Severity.HIGH if secret.severity == "high" else Severity.MEDIUM,
                category=Category.CREDENTIAL_EXPOSURE,
                location=Location(
                    file_path=secret_result.source_file,
                    start_line=secret.line_number,
                    end_line=secret.line_number,
                    start_column=secret.start_col,
                    end_column=secret.end_col,
                    snippet=secret.line_content
                ),
                cwe_id="CWE-798",
                owasp_id="ASI-04",  # Supply Chain Vulnerabilities
                confidence=confidence,
                tier=tier,
                remediation=Remediation(
                    description="Use environment variables or a secrets manager"
                )
            )
            all_findings.append(finding)

    # Run privilege scanner (AGENT-043~048)
    if not quiet and output_format == "terminal":
        console.print("[dim]Scanning for privilege issues...[/dim]")

    privilege_findings = privilege_scanner.scan_and_convert(path)
    all_findings.extend(privilege_findings)

    # Run TypeScript/JavaScript scanner
    if not quiet and output_format == "terminal":
        console.print("[dim]Scanning TypeScript/JavaScript files...[/dim]")

    try:
        from agent_audit.scanners.typescript_scanner import TypeScriptScanner
        ts_scanner = TypeScriptScanner(exclude_patterns=exclude_patterns)
        ts_findings = ts_scanner.scan_and_convert(path)
        all_findings.extend(ts_findings)
    except ImportError:
        pass  # TypeScript scanner not available (optional tree-sitter dep)

    # Run Solidity scanner (AGENT-083, AGENT-084)
    if not quiet and output_format == "terminal":
        console.print("[dim]Scanning Solidity contracts...[/dim]")

    try:
        from agent_audit.scanners.solidity_scanner import SolidityScanner
        sol_scanner = SolidityScanner(exclude_patterns=exclude_patterns)
        sol_findings = sol_scanner.scan_and_convert(path)
        all_findings.extend(sol_findings)
    except ImportError:
        pass  # Solidity scanner not available

    # Run Go scanner (AGENT-034, AGENT-041, AGENT-085, AGENT-026, AGENT-049)
    if not quiet and output_format == "terminal":
        console.print("[dim]Scanning Go files...[/dim]")

    try:
        from agent_audit.scanners.go_scanner import GoScanner
        go_scanner = GoScanner(exclude_patterns=exclude_patterns)
        go_findings = go_scanner.scan_and_convert(path)
        all_findings.extend(go_findings)
    except ImportError:
        pass  # Go scanner not available

    # Run skill scanners (AGENT-058~064)
    if not quiet and output_format == "terminal":
        console.print("[dim]Scanning SKILL.md files...[/dim]")

    skill_meta_scanner = SkillMetaScanner()
    skill_meta_results = skill_meta_scanner.scan(path)
    for skill_meta_result in skill_meta_results:
        scanned_files += 1
        meta_finding: SkillMetaFinding
        for meta_finding in skill_meta_result.security_findings:
            from agent_audit.models.risk import Location, Category
            from agent_audit.models.finding import Remediation

            severity_map = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
            }
            severity = severity_map.get(meta_finding.severity, Severity.MEDIUM)

            category_map = {
                'skill_daemon_persistence': Category.IDENTITY_PRIVILEGE_ABUSE,
                'skill_always_true_auto_invoke': Category.TRUST_EXPLOITATION,
                'skill_suspicious_network_endpoint': Category.SUPPLY_CHAIN_AGENTIC,
                'skill_sandbox_override': Category.UNEXPECTED_CODE_EXECUTION,
            }
            category = category_map.get(meta_finding.pattern_type, Category.SUPPLY_CHAIN_AGENTIC)

            from agent_audit.models.finding import confidence_to_tier
            finding = Finding(
                rule_id=meta_finding.rule_id,
                title=meta_finding.pattern_type.replace('_', ' ').title(),
                description=meta_finding.description,
                severity=severity,
                category=category,
                location=Location(
                    file_path=skill_meta_result.source_file,
                    start_line=meta_finding.line,
                    end_line=meta_finding.line,
                    snippet=meta_finding.snippet,
                ),
                owasp_id=meta_finding.owasp_id,
                confidence=meta_finding.confidence,
                tier=confidence_to_tier(meta_finding.confidence),
                remediation=Remediation(
                    description=f"Review skill metadata in '{Path(skill_meta_result.source_file).name}'"
                ),
            )
            all_findings.append(finding)

    skill_body_scanner = SkillBodyScanner()
    skill_body_results = skill_body_scanner.scan(path)
    for skill_body_result in skill_body_results:
        body_finding: SkillBodyFinding
        for body_finding in skill_body_result.security_findings:
            from agent_audit.models.risk import Location, Category
            from agent_audit.models.finding import Remediation, confidence_to_tier

            severity_map = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
            }
            severity = severity_map.get(body_finding.severity, Severity.MEDIUM)

            category_map = {
                'skill_obfuscated_shell': Category.SUPPLY_CHAIN_AGENTIC,
                'skill_critical_file_modification': Category.GOAL_HIJACK,
                'skill_fake_dependency': Category.SUPPLY_CHAIN_AGENTIC,
            }
            category = category_map.get(body_finding.pattern_type, Category.SUPPLY_CHAIN_AGENTIC)

            finding = Finding(
                rule_id=body_finding.rule_id,
                title=body_finding.pattern_type.replace('_', ' ').title(),
                description=body_finding.description,
                severity=severity,
                category=category,
                location=Location(
                    file_path=skill_body_result.source_file,
                    start_line=body_finding.line,
                    end_line=body_finding.line,
                    snippet=body_finding.snippet,
                ),
                owasp_id=body_finding.owasp_id,
                confidence=body_finding.confidence,
                tier=confidence_to_tier(body_finding.confidence),
                remediation=Remediation(
                    description=f"Review skill instructions in '{Path(skill_body_result.source_file).name}'"
                ),
            )
            all_findings.append(finding)

    # Profile-specific scanning (e.g., --profile defi)
    if profile:
        profile_lower = profile.lower()
        if profile_lower == 'defi':
            if not quiet and output_format == "terminal":
                console.print("[dim]Running DeFi profile scanners...[/dim]")
            try:
                from agent_audit.profiles.defi import scan_target as defi_scan
                from agent_audit.profiles.defi.rules import DeFiFinding
                defi_findings = defi_scan(str(path), exclude_patterns)
                # Convert DeFiFinding to agent-audit Finding model
                for df in defi_findings:
                    from agent_audit.models.risk import Location, Category
                    from agent_audit.models.finding import Remediation, confidence_to_tier
                    severity_map = {
                        'critical': Severity.CRITICAL,
                        'high': Severity.HIGH,
                        'medium': Severity.MEDIUM,
                        'low': Severity.LOW,
                        'info': Severity.LOW,
                    }
                    category_map = {
                        'ASI-01': Category.GOAL_HIJACK,
                        'ASI-02': Category.TOOL_MISUSE,
                        'ASI-03': Category.IDENTITY_PRIVILEGE_ABUSE,
                        'ASI-07': Category.INSECURE_INTER_AGENT_COMM,
                        'ASI-08': Category.CASCADING_FAILURES,
                        'ASI-09': Category.TRUST_EXPLOITATION,
                    }
                    finding = Finding(
                        rule_id=df.rule_id,
                        title=df.pattern_type.replace('_', ' ').title(),
                        description=df.message,
                        severity=severity_map.get(df.severity.value, Severity.MEDIUM),
                        category=category_map.get(df.owasp_agentic, Category.TOOL_MISUSE),
                        location=Location(
                            file_path=df.file_path,
                            start_line=df.line,
                            end_line=df.line,
                            start_column=df.column,
                            end_column=df.column,
                        ),
                        cwe_id=df.cwe,
                        owasp_id=df.owasp_agentic,
                        confidence=df.confidence,
                        tier=confidence_to_tier(df.confidence),
                        remediation=Remediation(description=df.remediation),
                    )
                    all_findings.append(finding)
                if not quiet and output_format == "terminal":
                    console.print(f"[dim]DeFi profile: {len(defi_findings)} findings[/dim]")
            except ImportError as e:
                if not quiet and output_format == "terminal":
                    console.print(f"[yellow]DeFi profile not available: {e}[/yellow]")
        else:
            if not quiet and output_format == "terminal":
                console.print(f"[yellow]Unknown profile: {profile}[/yellow]")

    # v0.9.0: Deduplicate findings (same-line, rule subsumption)
    # This reduces noise from redundant findings like AGENT-001 + AGENT-047 + AGENT-034
    # all firing on the same subprocess.run(shell=True) line
    findings_before = len(all_findings)
    all_findings = deduplicate_findings(all_findings)
    findings_deduped = findings_before - len(all_findings)
    if verbose and findings_deduped > 0 and output_format == "terminal":
        console.print(f"[dim]Deduplicated {findings_deduped} redundant findings[/dim]")

    # Apply ignore rules
    for finding in all_findings:
        ignore_manager.apply_to_finding(finding)

    # Note: Context-based confidence adjustment is handled by:
    # - AGENT-004: semantic_analyzer (called by secret_scanner)
    # - Other rules: Individual scanners apply their own confidence scores
    # We don't apply blanket post-processing here to avoid over-suppressing
    # intentionally vulnerable test fixtures used for scanner validation.

    # Filter by baseline if provided
    if baseline_path and baseline_path.exists():
        baseline = load_baseline(baseline_path)
        all_findings = filter_by_baseline(all_findings, baseline)
        if not quiet and output_format == "terminal":
            console.print(f"[dim]Filtered by baseline: {baseline_path}[/dim]")

    # Filter by minimum severity
    severity_order = {
        'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4
    }
    min_sev_value = severity_order.get(min_severity.lower(), 0)
    all_findings = [
        f for f in all_findings
        if severity_order.get(f.severity.value, 0) >= min_sev_value
    ]

    # Save baseline if requested
    if save_baseline_path:
        save_baseline(all_findings, save_baseline_path)
        if not quiet and output_format == "terminal":
            console.print(f"[dim]Saved baseline to: {save_baseline_path}[/dim]")

    # Output results
    if output_format == "terminal":
        format_scan_results(
            all_findings,
            str(path),
            scanned_files,
            verbose=verbose,
            quiet=quiet,
            min_tier=min_tier,
            no_color=no_color
        )
    elif output_format == "json":
        from agent_audit.cli.formatters.json import format_json
        json_output = format_json(all_findings, str(path), scanned_files)
        if output_path:
            output_path.write_text(json_output, encoding="utf-8")
        else:
            click.echo(json_output)
    elif output_format == "sarif":
        from agent_audit.cli.formatters.sarif import SARIFFormatter
        formatter = SARIFFormatter()
        if output_path:
            formatter.save(all_findings, output_path)
            if not quiet:
                console.print(f"[dim]SARIF output saved to: {output_path}[/dim]")
        else:
            console.print(formatter.format_to_string(all_findings))
    elif output_format == "markdown":
        _output_markdown(all_findings, str(path), output_path)

    # Determine exit code based on fail_on severity
    fail_sev_value = severity_order.get(fail_on_severity.lower(), 3)  # Default: high
    actionable_findings = [f for f in all_findings if f.is_actionable()]
    max_severity = max(
        (severity_order.get(f.severity.value, 0) for f in actionable_findings),
        default=0
    )

    # v0.15.0: --fail-on-new only fails if there are NEW findings (after baseline filter)
    if fail_on_new:
        # With --fail-on-new, only fail if there are any new findings at the fail_on level
        # all_findings has already been filtered by baseline at this point
        if actionable_findings and max_severity >= fail_sev_value:
            return 1
        return 0

    if max_severity >= fail_sev_value:
        return 1
    return 0


def _output_markdown(findings: List[Finding], scan_path: str, output_path: Optional[Path]):
    """Output findings as Markdown."""
    lines = [
        "# Agent Audit Security Report",
        "",
        f"**Scanned:** `{scan_path}`",
        f"**Findings:** {len(findings)}",
        "",
        "## Findings",
        "",
    ]

    for finding in findings:
        sev = finding.severity.value.upper()
        lines.append(f"### [{sev}] {finding.rule_id}: {finding.title}")
        lines.append("")
        lines.append(f"**Location:** `{finding.location.file_path}:{finding.location.start_line}`")
        lines.append("")
        if finding.location.snippet:
            lines.append("```python")
            lines.append(finding.location.snippet)
            lines.append("```")
            lines.append("")
        lines.append(finding.description)
        lines.append("")
        if finding.remediation:
            lines.append(f"**Fix:** {finding.remediation.description}")
            lines.append("")
        lines.append("---")
        lines.append("")

    md_content = "\n".join(lines)

    if output_path:
        output_path.write_text(md_content, encoding="utf-8")
    else:
        console.print(md_content)


@click.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['terminal', 'json', 'sarif', 'markdown']),
              default='terminal', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--severity', '-s',
              type=click.Choice(['critical', 'high', 'medium', 'low', 'info']),
              default='low', help='Minimum severity to report')
@click.option('--rules', '-r', type=click.Path(exists=True),
              multiple=True, help='Additional rule files')
@click.option('--rules-dir', type=click.Path(exists=True, file_okay=False),
              help='Directory containing custom YAML rule files')
@click.option('--fail-on',
              type=click.Choice(['critical', 'high', 'medium', 'low']),
              default='high', help='Exit with error if findings at this level')
@click.option('--baseline', type=click.Path(),
              help='Baseline file - only report new findings')
@click.option('--save-baseline', '--create-baseline', type=click.Path(),
              help='Save current findings as baseline')
@click.option('--fail-on-new', is_flag=True, default=False,
              help='Exit with error only for new findings not in baseline')
@click.option('--min-tier',
              type=click.Choice(['BLOCK', 'WARN', 'INFO', 'SUPPRESSED'], case_sensitive=False),
              default=None,
              help='Minimum tier to display (default: WARN, or INFO with --verbose)')
@click.option('--no-color', is_flag=True, default=False,
              help='Disable colored output (for CI/CD environments)')
@click.option('--dynamic', is_flag=True, default=False,
              help='Enable dynamic MCP server scanning (connect and probe running servers)')
@click.option('--dynamic-only', is_flag=True, default=False,
              help='Only run dynamic scanning (skip static analysis)')
@click.option('--mcp-baseline', type=click.Path(),
              help='MCP baseline file for drift detection (used with --dynamic)')
@click.option('--dynamic-timeout', type=int, default=120,
              help='Timeout for dynamic MCP scanning in seconds')
@click.option('--profile', '-p', type=str, default=None,
              help='Load domain-specific rules (e.g., defi)')
@click.pass_context
def scan(ctx: click.Context, path: str, output_format: str, output: Optional[str],
         severity: str, rules: tuple, rules_dir: Optional[str], fail_on: str,
         baseline: Optional[str], save_baseline: Optional[str],
         fail_on_new: bool, min_tier: Optional[str], no_color: bool,
         dynamic: bool, dynamic_only: bool, mcp_baseline: Optional[str],
         dynamic_timeout: int, profile: Optional[str]):
    """
    Scan agent code and configurations for security issues.

    PATH is the directory or file to scan. Defaults to current directory.

    Examples:

        agent-audit scan ./my-agent

        agent-audit scan . --format sarif --output results.sarif

        agent-audit scan . --severity critical --fail-on critical

        agent-audit scan . --baseline baseline.json

        agent-audit scan . --save-baseline baseline.json

        agent-audit scan . --dynamic --mcp-baseline .agent-audit-baseline.json
    """
    exit_code = run_scan(
        path=Path(path),
        output_format=output_format,
        output_path=Path(output) if output else None,
        min_severity=severity,
        additional_rules=list(rules),
        fail_on_severity=fail_on,
        baseline_path=Path(baseline) if baseline else None,
        save_baseline_path=Path(save_baseline) if save_baseline else None,
        rules_dir=Path(rules_dir) if rules_dir else None,
        verbose=ctx.obj.get('verbose', False),
        quiet=ctx.obj.get('quiet', False),
        min_tier=min_tier.upper() if min_tier else None,
        no_color=no_color,
        fail_on_new=fail_on_new,
        profile=profile
    )

    ctx.exit(exit_code)
