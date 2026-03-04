"""
MCP Baseline Drift Detection — Rug Pull detection for MCP servers.

Phase 1: Inspect — connect to MCP server, snapshot tools/resources/prompts
Phase 2: Scan  — compare current state against baseline, generate drift findings

Rule: AGENT-054 (CWE-494)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class DriftType(Enum):
    """Types of baseline drift."""
    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    TOOL_MODIFIED = "tool_modified"
    RESOURCE_ADDED = "resource_added"
    RESOURCE_REMOVED = "resource_removed"
    RESOURCE_MODIFIED = "resource_modified"
    PROMPT_ADDED = "prompt_added"
    PROMPT_REMOVED = "prompt_removed"
    PROMPT_MODIFIED = "prompt_modified"
    SERVER_ADDED = "server_added"
    SERVER_REMOVED = "server_removed"


# Base confidence per drift type
DRIFT_CONFIDENCE: Dict[str, float] = {
    "tool_added": 0.80,
    "tool_removed": 0.50,
    "tool_modified": 0.85,
    "resource_added": 0.70,
    "resource_removed": 0.40,
    "resource_modified": 0.75,
    "prompt_added": 0.75,
    "prompt_removed": 0.40,
    "prompt_modified": 0.85,
    "server_added": 0.80,
    "server_removed": 0.30,
}

# Drift type to pattern_type mapping (for RuleEngine integration)
DRIFT_TO_PATTERN_TYPE: Dict[str, str] = {
    "tool_added": "mcp_tool_drift_added",
    "tool_removed": "mcp_tool_drift_removed",
    "tool_modified": "mcp_tool_drift_modified",
    "resource_added": "mcp_resource_drift_added",
    "resource_removed": "mcp_resource_drift_modified",
    "resource_modified": "mcp_resource_drift_modified",
    "prompt_added": "mcp_prompt_drift_added",
    "prompt_removed": "mcp_prompt_drift_modified",
    "prompt_modified": "mcp_prompt_drift_modified",
    "server_added": "mcp_server_drift_added",
    "server_removed": "mcp_server_drift_added",
}

BASELINE_VERSION = "1.0"


@dataclass
class ComponentSnapshot:
    """Snapshot of a single tool/resource/prompt component."""
    description: str = ""
    description_hash: str = ""
    schema: Optional[Dict[str, Any]] = None
    schema_hash: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ServerSnapshot:
    """Snapshot of a single MCP server."""
    config_hash: str = ""
    tools: Dict[str, ComponentSnapshot] = field(default_factory=dict)
    resources: Dict[str, ComponentSnapshot] = field(default_factory=dict)
    prompts: Dict[str, ComponentSnapshot] = field(default_factory=dict)
    snapshot_at: str = ""


@dataclass
class BaselineData:
    """Complete baseline data for all MCP servers."""
    version: str = BASELINE_VERSION
    created_at: str = ""
    agent_audit_version: str = ""
    servers: Dict[str, ServerSnapshot] = field(default_factory=dict)


@dataclass
class DriftFinding:
    """A single drift finding between baseline and current state."""
    drift_type: str
    server_name: str
    component_name: str
    component_type: str  # "tool", "resource", "prompt", "server"
    details: str
    confidence: float
    pattern_type: str = ""

    def __post_init__(self):
        if not self.pattern_type:
            self.pattern_type = DRIFT_TO_PATTERN_TYPE.get(self.drift_type, "mcp_tool_drift_modified")


def _compute_hash(data: Any) -> str:
    """Compute SHA256 hash of JSON-serializable data (canonical form)."""
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=True, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class MCPBaselineManager:
    """Manage MCP baseline creation, loading, and drift detection."""

    def __init__(self, baseline_path: str = ".agent-audit-baseline.json"):
        self.baseline_path = baseline_path

    def create_baseline(
        self,
        inspection_results: Dict[str, Any],
        agent_audit_version: str = "0.17.0"
    ) -> BaselineData:
        """
        Create a baseline from MCPInspector results.

        Args:
            inspection_results: Dict of server_name -> inspection data
            agent_audit_version: Current agent-audit version

        Returns:
            BaselineData ready for saving
        """
        now = datetime.utcnow().isoformat() + "Z"
        baseline = BaselineData(
            version=BASELINE_VERSION,
            created_at=now,
            agent_audit_version=agent_audit_version,
        )

        for server_name, data in inspection_results.items():
            snapshot = ServerSnapshot(
                config_hash=_compute_hash(data.get("config", {})),
                snapshot_at=now,
            )

            # Snapshot tools
            for tool in data.get("tools", []):
                name = tool.get("name", "unknown")
                desc = tool.get("description", "")
                schema = tool.get("inputSchema", {})
                snapshot.tools[name] = ComponentSnapshot(
                    description=desc,
                    description_hash=_compute_hash(desc),
                    schema=schema,
                    schema_hash=_compute_hash(schema) if schema else None,
                )

            # Snapshot resources
            for resource in data.get("resources", []):
                uri = resource.get("uri", resource.get("name", "unknown"))
                desc = resource.get("description", "")
                snapshot.resources[uri] = ComponentSnapshot(
                    description=desc,
                    description_hash=_compute_hash(desc),
                    extra={
                        "name": resource.get("name", ""),
                        "mimeType": resource.get("mimeType", ""),
                    },
                )

            # Snapshot prompts
            for prompt in data.get("prompts", []):
                name = prompt.get("name", "unknown")
                desc = prompt.get("description", "")
                args = prompt.get("arguments", [])
                snapshot.prompts[name] = ComponentSnapshot(
                    description=desc,
                    description_hash=_compute_hash(desc),
                    extra={"arguments": args},
                    schema_hash=_compute_hash(args) if args else None,
                )

            baseline.servers[server_name] = snapshot

        return baseline

    def save_baseline(self, baseline: BaselineData, path: Optional[str] = None) -> None:
        """Save baseline to JSON file."""
        target = path or self.baseline_path
        data = self._baseline_to_dict(baseline)
        Path(target).write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

    def load_baseline(self, path: Optional[str] = None) -> Optional[BaselineData]:
        """
        Load baseline from JSON file.

        Returns None if file doesn't exist or version is incompatible.
        """
        target = path or self.baseline_path
        target_path = Path(target)

        if not target_path.exists():
            logger.warning("Baseline file not found: %s", target)
            return None

        try:
            raw = json.loads(target_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load baseline: %s", e)
            return None

        version = raw.get("version", "")
        if version != BASELINE_VERSION:
            logger.error(
                "Baseline version mismatch: expected %s, got %s",
                BASELINE_VERSION, version
            )
            return None

        return self._dict_to_baseline(raw)

    def detect_drift(
        self,
        current: Dict[str, Any],
        baseline: BaselineData
    ) -> List[DriftFinding]:
        """
        Compare current MCP state against baseline and return drift findings.

        Args:
            current: Dict of server_name -> inspection data (same format as create_baseline input)
            baseline: Previously saved baseline

        Returns:
            List of DriftFinding for each detected drift
        """
        findings: List[DriftFinding] = []

        current_servers = set(current.keys())
        baseline_servers = set(baseline.servers.keys())

        # Server-level drift
        for added in current_servers - baseline_servers:
            findings.append(DriftFinding(
                drift_type="server_added",
                server_name=added,
                component_name=added,
                component_type="server",
                details=f"New server '{added}' not in baseline",
                confidence=DRIFT_CONFIDENCE["server_added"],
            ))

        for removed in baseline_servers - current_servers:
            findings.append(DriftFinding(
                drift_type="server_removed",
                server_name=removed,
                component_name=removed,
                component_type="server",
                details=f"Server '{removed}' removed since baseline",
                confidence=DRIFT_CONFIDENCE["server_removed"],
            ))

        # Per-server component drift
        for server_name in current_servers & baseline_servers:
            server_data = current[server_name]
            server_baseline = baseline.servers[server_name]

            # Tool drift
            findings.extend(self._diff_components(
                server_name=server_name,
                current_items=server_data.get("tools", []),
                baseline_items=server_baseline.tools,
                component_type="tool",
                name_key="name",
            ))

            # Resource drift
            findings.extend(self._diff_components(
                server_name=server_name,
                current_items=server_data.get("resources", []),
                baseline_items=server_baseline.resources,
                component_type="resource",
                name_key="uri",
                fallback_key="name",
            ))

            # Prompt drift
            findings.extend(self._diff_components(
                server_name=server_name,
                current_items=server_data.get("prompts", []),
                baseline_items=server_baseline.prompts,
                component_type="prompt",
                name_key="name",
            ))

        # Post-processing: boost confidence for poisoning in modified descriptions
        self._apply_confidence_adjustments(findings, current, baseline)

        return findings

    def _diff_components(
        self,
        server_name: str,
        current_items: List[Dict[str, Any]],
        baseline_items: Dict[str, ComponentSnapshot],
        component_type: str,
        name_key: str = "name",
        fallback_key: Optional[str] = None,
    ) -> List[DriftFinding]:
        """Diff a single component type (tools, resources, prompts)."""
        findings: List[DriftFinding] = []

        # Build current map
        current_map: Dict[str, Dict[str, Any]] = {}
        for item in current_items:
            key = item.get(name_key, "")
            if not key and fallback_key:
                key = item.get(fallback_key, "unknown")
            current_map[key] = item

        current_names = set(current_map.keys())
        baseline_names = set(baseline_items.keys())

        added_type = f"{component_type}_added"
        removed_type = f"{component_type}_removed"
        modified_type = f"{component_type}_modified"

        # Added
        for name in current_names - baseline_names:
            findings.append(DriftFinding(
                drift_type=added_type,
                server_name=server_name,
                component_name=name,
                component_type=component_type,
                details=f"New {component_type} '{name}' added to '{server_name}'",
                confidence=DRIFT_CONFIDENCE.get(added_type, 0.70),
            ))

        # Removed
        for name in baseline_names - current_names:
            findings.append(DriftFinding(
                drift_type=removed_type,
                server_name=server_name,
                component_name=name,
                component_type=component_type,
                details=f"{component_type.title()} '{name}' removed from '{server_name}'",
                confidence=DRIFT_CONFIDENCE.get(removed_type, 0.40),
            ))

        # Modified
        for name in current_names & baseline_names:
            current_item = current_map[name]
            baseline_snap = baseline_items[name]

            # Compare description
            current_desc = current_item.get("description", "")
            desc_hash = _compute_hash(current_desc)
            if desc_hash != baseline_snap.description_hash:
                findings.append(DriftFinding(
                    drift_type=modified_type,
                    server_name=server_name,
                    component_name=name,
                    component_type=component_type,
                    details=(
                        f"{component_type.title()} '{name}' description changed on '{server_name}'"
                    ),
                    confidence=DRIFT_CONFIDENCE.get(modified_type, 0.75),
                ))

            # Compare schema (for tools)
            if baseline_snap.schema_hash:
                current_schema = current_item.get("inputSchema", current_item.get("arguments", {}))
                schema_hash = _compute_hash(current_schema)
                if schema_hash != baseline_snap.schema_hash:
                    findings.append(DriftFinding(
                        drift_type=modified_type,
                        server_name=server_name,
                        component_name=name,
                        component_type=component_type,
                        details=(
                            f"{component_type.title()} '{name}' schema/arguments changed "
                            f"on '{server_name}'"
                        ),
                        confidence=DRIFT_CONFIDENCE.get(modified_type, 0.75),
                    ))

        return findings

    def _apply_confidence_adjustments(
        self,
        findings: List[DriftFinding],
        current: Dict[str, Any],
        baseline: BaselineData
    ) -> None:
        """Apply confidence adjustments for special cases."""
        from agent_audit.analysis.tool_description_analyzer import ToolDescriptionAnalyzer

        for finding in findings:
            # Boost: MODIFIED and new description contains poisoning
            if finding.drift_type.endswith("_modified"):
                server_data = current.get(finding.server_name, {})
                component_lists = {
                    "tool": server_data.get("tools", []),
                    "resource": server_data.get("resources", []),
                    "prompt": server_data.get("prompts", []),
                }
                items = component_lists.get(finding.component_type, [])
                for item in items:
                    item_name = item.get("name", item.get("uri", ""))
                    if item_name == finding.component_name:
                        desc = item.get("description", "")
                        if desc and ToolDescriptionAnalyzer.has_poisoning(desc):
                            finding.confidence = 0.95
                        break

            # Boost: ADDED with similar name to existing tool (possible shadowing)
            if finding.drift_type.endswith("_added") and finding.component_type == "tool":
                server_snap = baseline.servers.get(finding.server_name)
                if server_snap:
                    from agent_audit.scanners.mcp_config_scanner import MCPConfigScanner
                    for existing_name in server_snap.tools:
                        dist = MCPConfigScanner._levenshtein_distance(
                            finding.component_name.lower(),
                            existing_name.lower()
                        )
                        if dist <= 2 and len(finding.component_name) > 5:
                            finding.confidence = min(0.95, finding.confidence + 0.10)
                            break

    # =========================================================================
    # Serialization helpers
    # =========================================================================

    @staticmethod
    def _baseline_to_dict(baseline: BaselineData) -> Dict[str, Any]:
        """Convert BaselineData to JSON-serializable dict."""
        servers = {}
        for name, snap in baseline.servers.items():
            tools = {}
            for t_name, t_snap in snap.tools.items():
                tools[t_name] = {
                    "description": t_snap.description,
                    "description_hash": t_snap.description_hash,
                    "input_schema": t_snap.schema,
                    "input_schema_hash": t_snap.schema_hash,
                }
            resources = {}
            for r_key, r_snap in snap.resources.items():
                resources[r_key] = {
                    "description": r_snap.description,
                    "description_hash": r_snap.description_hash,
                    **r_snap.extra,
                }
            prompts = {}
            for p_name, p_snap in snap.prompts.items():
                prompts[p_name] = {
                    "description": p_snap.description,
                    "description_hash": p_snap.description_hash,
                    "arguments_hash": p_snap.schema_hash,
                    **p_snap.extra,
                }
            servers[name] = {
                "config_hash": snap.config_hash,
                "tools": tools,
                "resources": resources,
                "prompts": prompts,
                "snapshot_at": snap.snapshot_at,
            }
        return {
            "version": baseline.version,
            "created_at": baseline.created_at,
            "agent_audit_version": baseline.agent_audit_version,
            "servers": servers,
        }

    @staticmethod
    def _dict_to_baseline(raw: Dict[str, Any]) -> BaselineData:
        """Convert JSON dict back to BaselineData."""
        baseline = BaselineData(
            version=raw.get("version", BASELINE_VERSION),
            created_at=raw.get("created_at", ""),
            agent_audit_version=raw.get("agent_audit_version", ""),
        )
        for server_name, server_data in raw.get("servers", {}).items():
            snap = ServerSnapshot(
                config_hash=server_data.get("config_hash", ""),
                snapshot_at=server_data.get("snapshot_at", ""),
            )
            for t_name, t_data in server_data.get("tools", {}).items():
                snap.tools[t_name] = ComponentSnapshot(
                    description=t_data.get("description", ""),
                    description_hash=t_data.get("description_hash", ""),
                    schema=t_data.get("input_schema"),
                    schema_hash=t_data.get("input_schema_hash"),
                )
            for r_key, r_data in server_data.get("resources", {}).items():
                snap.resources[r_key] = ComponentSnapshot(
                    description=r_data.get("description", ""),
                    description_hash=r_data.get("description_hash", ""),
                    extra={
                        k: v for k, v in r_data.items()
                        if k not in ("description", "description_hash")
                    },
                )
            for p_name, p_data in server_data.get("prompts", {}).items():
                snap.prompts[p_name] = ComponentSnapshot(
                    description=p_data.get("description", ""),
                    description_hash=p_data.get("description_hash", ""),
                    schema_hash=p_data.get("arguments_hash"),
                    extra={
                        k: v for k, v in p_data.items()
                        if k not in ("description", "description_hash", "arguments_hash")
                    },
                )
            baseline.servers[server_name] = snap
        return baseline
