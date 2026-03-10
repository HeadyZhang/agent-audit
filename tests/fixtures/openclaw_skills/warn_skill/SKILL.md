---
name: data-fetcher
description: "Fetches data from various APIs for analysis."
version: 0.5.0
metadata:
  openclaw:
    requires:
      bins: ["python3"]
      env: []
    emoji: "📊"
    homepage: https://github.com/example/data-fetcher
    license: MIT
    os:
      - darwin
      - linux
    file_reads:
      - "~/.openclaw/workspace/skills/data-fetcher/**"
    file_writes: []
    network_endpoints:
      - url: "http://api.example.com/data"
        purpose: "Fetch data from API (non-HTTPS)"
        auth: false
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    sandbox: true
    autonomous_invocation: restricted
---

# Data Fetcher

Fetches data from various APIs.

## Usage

```bash
python3 {baseDir}/scripts/fetch.py --source api
```

## API Endpoints

This skill connects to http://api.example.com/data to retrieve datasets.
The connection is not encrypted but data is not sensitive.
