#!/bin/bash
# Cut every Havoc agent off: stop the teamserver and close its listener ports.
# ponytail: agents stay resident on their hosts until they exit or the range
# is reverted to its baseline snapshot; this only removes what they call home to.
set -u
systemctl stop havoc 2>/dev/null
for port in ${HAVOC_PORTS:-8080 9443 8443}; do
    ufw deny "$port/tcp" >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport "$port" -j DROP
done
echo "Havoc teamserver stopped; listener ports ${HAVOC_PORTS:-8080 9443 8443} closed."
echo "Agents remain on their hosts until they exit; revert the range snapshot to remove them."
