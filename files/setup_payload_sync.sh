#!/bin/bash
# setup_payload_sync.sh - Configure systemd service and timer

# Create systemd service file
cat > /etc/systemd/system/payload-sync.service << EOF
[Unit]
Description=Secure Payload Sync Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/root/Tools/secure_payload_sync.sh
User=root
Group=root
# Security hardening
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
# Hide process information
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer with randomized schedule
cat > /etc/systemd/system/payload-sync.timer << EOF
[Unit]
Description=Secure Payload Sync Timer
Requires=payload-sync.service

[Timer]
# Run every 30-60 minutes with randomization
OnBootSec=5min
OnUnitActiveSec=30m
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Copy script to proper location
cp secure_payload_sync.sh /root/Tools/
chmod 700 /root/Tools/secure_payload_sync.sh

# Enable and start timer
systemctl daemon-reload
systemctl enable payload-sync.timer
systemctl start payload-sync.timer

echo "Payload sync service installed and timer started"