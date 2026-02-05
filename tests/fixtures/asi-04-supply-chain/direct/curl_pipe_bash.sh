#!/bin/bash
# ASI-04: Curl pipe to bash vulnerability
# Rule: AGENT-015
# Expected: TRUE POSITIVE at line 11
# owasp_id: ASI-04

install_tool() {
    local url="$1"
    # VULNERABILITY: curl pipe to bash - arbitrary code execution
    curl -fsSL "$url" | bash
}

install_tool "https://example.com/install.sh"
