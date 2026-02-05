#!/bin/bash
# Vuln: creating systemd service for persistent privilege.
# Expected: AGENT-043

cat > /etc/systemd/system/agent-gateway.service << 'EOF'
[Unit]
Description=Agent Gateway Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/agent-gateway
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl enable agent-gateway.service  # LINE 17
systemctl start agent-gateway.service
