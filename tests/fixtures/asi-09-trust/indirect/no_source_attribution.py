"""
ASI-09: No source attribution in agent output.
Rule: AGENT-023
Expected: TRUE POSITIVE at line 16
owasp_id: ASI-09
"""


class OpaqueAgent:
    def answer(self, query: str) -> str:
        """Answer query without source attribution."""
        # Gather info from various sources
        sources = self._gather_sources(query)
        # VULNERABILITY: No transparency about sources
        return self._synthesize(sources)
    
    def _gather_sources(self, query):
        return []
    
    def _synthesize(self, sources):
        return "Answer without attribution"
