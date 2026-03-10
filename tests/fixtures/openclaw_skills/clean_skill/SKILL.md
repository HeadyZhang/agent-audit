---
name: weather-checker
description: "A simple weather checking skill that fetches current weather data."
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins: ["python3"]
      env: []
    emoji: "🌤️"
    homepage: https://github.com/example/weather-checker
    license: MIT
    os:
      - darwin
      - linux
    file_reads:
      - "~/.openclaw/workspace/skills/weather-checker/**"
    file_writes: []
    network_endpoints:
      - url: "https://api.openweathermap.org/data/2.5/weather"
        purpose: "Fetch current weather data"
        auth: true
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    sandbox: true
    autonomous_invocation: restricted
---

# Weather Checker

Check the current weather for any location.

## Usage

```bash
python3 {baseDir}/scripts/check-weather.py "New York"
```

## How It Works

1. Takes a location name as input
2. Calls the OpenWeatherMap API
3. Returns temperature, conditions, and humidity

## Requirements

- An OpenWeatherMap API key set as `OPENWEATHER_API_KEY` environment variable
- Python 3.8+
