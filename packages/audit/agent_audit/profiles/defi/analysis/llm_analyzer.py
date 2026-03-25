"""LLM semantic analyzer - Claude API deep code review.

Uses Claude API for deep semantic analysis of DeFi code that static
analysis cannot cover. Returns empty list when ANTHROPIC_API_KEY is
not set (no crash). LLM findings are capped at 0.80 confidence.
"""
from __future__ import annotations

import json
import os
from typing import Dict, List

from agent_audit.profiles.defi.rules import DeFiFinding, Severity


class LLMAnalyzer:
    """DeFi code semantic review via Claude API."""

    MAX_CONFIDENCE = 0.80

    SYSTEM_PROMPT = (
        "You are a senior DeFi security auditor. Analyze the provided code "
        "for security vulnerabilities related to:\n"
        "1. Private key management (hardcoded keys, insecure storage, missing HSM/KMS)\n"
        "2. Transaction safety (missing amount limits, slippage protection, gas limits)\n"
        "3. Access control (missing authentication, authorization bypass)\n"
        "4. Prompt injection paths (user input flowing to transaction parameters)\n"
        "5. Flash loan attack surfaces (price oracle manipulation, callback reentrancy)\n"
        "6. MEV vulnerability (sandwich attack, front-running exposure)\n\n"
        "For each vulnerability found, respond in JSON format:\n"
        '{\n'
        '  "findings": [\n'
        '    {\n'
        '      "rule_id": "LLM-001",\n'
        '      "title": "Brief title",\n'
        '      "severity": "critical|high|medium|low",\n'
        '      "file": "filename",\n'
        '      "line_start": 10,\n'
        '      "line_end": 20,\n'
        '      "description": "Detailed explanation of the vulnerability and its impact",\n'
        '      "attack_scenario": "Step-by-step attack path",\n'
        '      "remediation": "Specific fix recommendation with code example"\n'
        '    }\n'
        '  ]\n'
        '}\n\n'
        "Be precise. Only report real vulnerabilities, not style issues. "
        'If no vulnerabilities found, return {"findings": []}.'
    )

    def __init__(self) -> None:
        self.api_key = os.environ.get('ANTHROPIC_API_KEY')
        self.available = self.api_key is not None

    def is_available(self) -> bool:
        """Check if API key is configured."""
        return self.available

    def analyze_files(self, file_contents: Dict[str, str]) -> List[DeFiFinding]:
        """Analyze multiple files via Claude API."""
        if not self.available:
            return []

        try:
            import anthropic
        except ImportError:
            return []

        code_context = "\n\n".join(
            f"=== File: {path} ===\n```\n{content[:8000]}\n```"
            for path, content in file_contents.items()
        )

        user_prompt = (
            "Analyze the following DeFi/blockchain project code "
            "for security vulnerabilities:\n\n"
            f"{code_context}\n\n"
            "Provide your findings in the JSON format specified in your instructions."
        )

        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            response_text = response.content[0].text
            # Extract JSON from markdown code blocks if present
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]

            data = json.loads(response_text)
            return self._convert_findings(data.get('findings', []))

        except Exception as e:
            return [DeFiFinding(
                rule_id='INFO',
                pattern_type='llm_analysis_error',
                file_path='',
                line=0,
                confidence=1.0,
                severity=Severity.INFO,
                message=f'LLM analysis error: {str(e)[:100]}',
            )]

    def _convert_findings(self, llm_findings: list) -> List[DeFiFinding]:
        """Convert LLM JSON results to DeFiFinding list."""
        results: List[DeFiFinding] = []
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
        }
        confidence_map = {
            Severity.CRITICAL: 0.78,
            Severity.HIGH: 0.72,
            Severity.MEDIUM: 0.60,
            Severity.LOW: 0.45,
        }

        for f in llm_findings:
            sev = severity_map.get(f.get('severity', 'medium'), Severity.MEDIUM)
            conf = min(self.MAX_CONFIDENCE, confidence_map.get(sev, 0.60))

            description = f.get('description', '')
            attack = f.get('attack_scenario', '')
            remediation = f.get('remediation', '')
            full_message = description
            if attack:
                full_message += f' | Attack: {attack}'

            results.append(DeFiFinding(
                rule_id=f.get('rule_id', 'LLM-001'),
                pattern_type='llm_semantic_finding',
                file_path=f.get('file', ''),
                line=f.get('line_start', 0),
                confidence=conf,
                severity=sev,
                message=full_message[:300],
                remediation=remediation[:200],
            ))
        return results
