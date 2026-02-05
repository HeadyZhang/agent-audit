#!/bin/bash
# Vuln: NOPASSWD sudoers config.
# Expected: AGENT-044
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/agent-runner  # LINE 4
