# Agent-Vuln-Bench Evaluation Environment
# Docker image for reproducible benchmark evaluation
#
# Usage:
#   docker build -t agent-vuln-bench .
#   docker run -v /path/to/agent-audit:/opt/agent-audit agent-vuln-bench
#
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python tools
RUN pip install --no-cache-dir \
    pyyaml \
    bandit \
    semgrep \
    rich \
    click

# Copy benchmark files
COPY . /opt/agent-vuln-bench

# Install agent-audit (mount from host or copy)
# Option 1: Mount from host
# docker run -v /path/to/agent-audit:/opt/agent-audit agent-vuln-bench
# Option 2: Install from PyPI (when available)
# RUN pip install agent-audit

WORKDIR /opt/agent-vuln-bench

# Set up environment
ENV PYTHONPATH=/opt/agent-audit/packages/audit:$PYTHONPATH
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "harness/run_eval.py"]
CMD ["--tool", "agent-audit", "--dataset", "knowns"]
