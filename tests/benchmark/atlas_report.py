#!/usr/bin/env python3
"""
Generate MITRE ATLAS coverage report for agent-audit.

Usage:
    python tests/benchmark/atlas_report.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Set

import yaml


def load_mappings() -> Dict[str, Any]:
    """Load MITRE ATLAS mappings from YAML file."""
    mapping_file = Path(__file__).parent.parent.parent / "rules" / "mappings" / "mitre_atlas.yaml"
    with open(mapping_file) as f:
        return yaml.safe_load(f)


def generate_report() -> None:
    """Generate and print MITRE ATLAS coverage report."""
    data = load_mappings()
    mappings = data.get("mappings", {})

    # Count techniques covered
    techniques: Set[str] = set()
    tactics: Set[str] = set()
    rules_by_technique: Dict[str, list] = {}
    rules_by_tactic: Dict[str, list] = {}

    for rule_id, info in mappings.items():
        atlas_id = info.get("atlas_id")
        technique = info.get("technique", "Unknown")
        tactic = info.get("tactic", "Unknown")

        if atlas_id:
            techniques.add(atlas_id)
            if atlas_id not in rules_by_technique:
                rules_by_technique[atlas_id] = []
            rules_by_technique[atlas_id].append(rule_id)

        if tactic:
            tactics.add(tactic)
            if tactic not in rules_by_tactic:
                rules_by_tactic[tactic] = []
            rules_by_tactic[tactic].append(rule_id)

    print("=" * 60)
    print("MITRE ATLAS COVERAGE REPORT")
    print("=" * 60)
    print(f"\nATLAS Version: {data.get('atlas_version', 'unknown')}")
    print(f"Total Rules Mapped: {len(mappings)}")
    print(f"Unique Techniques: {len(techniques)}")
    print(f"Tactics Covered: {len(tactics)}")

    print("\n" + "-" * 60)
    print("TECHNIQUE COVERAGE")
    print("-" * 60)
    for tech in sorted(techniques):
        rules = rules_by_technique.get(tech, [])
        tech_name = ""
        for rule_id in rules:
            if rule_id in mappings:
                tech_name = mappings[rule_id].get("technique", "")
                break
        print(f"  {tech}: {tech_name}")
        for rule in sorted(rules):
            notes = mappings.get(rule, {}).get("notes", "")
            print(f"    - {rule}: {notes}")

    print("\n" + "-" * 60)
    print("TACTIC COVERAGE")
    print("-" * 60)
    for tactic in sorted(tactics):
        rules = rules_by_tactic.get(tactic, [])
        print(f"  {tactic}: {len(rules)} rules")
        for rule in sorted(rules)[:5]:
            print(f"    - {rule}")
        if len(rules) > 5:
            print(f"    ... and {len(rules) - 5} more")

    # ATT&CK cross-references
    attck_refs: Set[str] = set()
    for rule_id, info in mappings.items():
        related = info.get("related", [])
        for ref in related:
            if ref.startswith("T"):
                attck_refs.add(ref)

    if attck_refs:
        print("\n" + "-" * 60)
        print("ATT&CK CROSS-REFERENCES")
        print("-" * 60)
        for ref in sorted(attck_refs):
            print(f"  - {ref}")

    print("\n" + "=" * 60)
    print(f"SUMMARY: {len(mappings)} rules mapped to {len(techniques)} ATLAS techniques")
    print("=" * 60)


if __name__ == "__main__":
    generate_report()
