#!/bin/bash
# Attack Box - Git Repositories Cloning Script
# Clones security tool repositories with enhanced feedback

# Get OPERATOR_DIR from environment or use default
OPERATOR_DIR="${OPERATOR_DIR:-/root/operator}"

echo "================================================================"
echo "GIT REPOSITORIES CLONING STARTED"
echo "================================================================"

REPOS=(
  "https://github.com/SecureAuthCorp/impacket.git"
  "https://github.com/danielmiessler/SecLists.git"
  "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
  "https://github.com/fuzzdb-project/fuzzdb.git"
  "https://github.com/1N3/Sn1per.git"
  "https://github.com/maurosoria/dirsearch.git"
  "https://github.com/OJ/gobuster.git"
  "https://github.com/aboul3la/Sublist3r.git"
  "https://github.com/laramies/theHarvester.git"
  "https://github.com/Tib3rius/AutoRecon.git"
  "https://github.com/carlospolop/PEASS-ng.git"
  "https://github.com/rebootuser/LinEnum.git"
  "https://github.com/mzet-/linux-exploit-suggester.git"
  "https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git"
  "https://github.com/PowerShellMafia/PowerSploit.git"
  "https://github.com/BloodHoundAD/BloodHound.git"
  "https://github.com/EmpireProject/Empire.git"
  "https://github.com/cobbr/Covenant.git"
  "https://github.com/byt3bl33d3r/CrackMapExec.git"
  "https://github.com/Hackplayers/evil-winrm.git"
)

REPO_NAMES=(
  "impacket-dev"
  "SecLists"
  "PayloadsAllTheThings"
  "fuzzdb"
  "Sn1per"
  "dirsearch-dev"
  "gobuster-dev"
  "Sublist3r"
  "theHarvester-dev"
  "AutoRecon"
  "PEASS-ng"
  "LinEnum"
  "linux-exploit-suggester"
  "Windows-Exploit-Suggester"
  "PowerSploit"
  "BloodHound"
  "Empire"
  "Covenant"
  "CrackMapExec-dev"
  "evil-winrm"
)

TOTAL=${#REPOS[@]}
CURRENT=0
FAILED=0
SUCCESS=0

# Create git directory if it doesn't exist
mkdir -p "$OPERATOR_DIR/tools/git"
cd "$OPERATOR_DIR/tools/git"

for i in "${!REPOS[@]}"; do
  CURRENT=$((CURRENT + 1))
  repo="${REPOS[$i]}"
  name="${REPO_NAMES[$i]}"
  
  echo ""
  echo "[$CURRENT/$TOTAL] Cloning $name..."
  echo "Repository: $repo"
  echo "Progress: $(( CURRENT * 100 / TOTAL ))%"
  echo "Started: $(date '+%H:%M:%S')"
  
  if [ -d "$name" ]; then
    echo "Repository $name already exists, updating..."
    cd "$name"
    if timeout 300 git pull origin main 2>/dev/null || timeout 300 git pull origin master 2>/dev/null; then
      SUCCESS=$((SUCCESS + 1))
      echo "✓ $name updated successfully"
    else
      FAILED=$((FAILED + 1))
      echo "✗ $name update failed"
    fi
    cd ..
  else
    if timeout 300 git clone --depth 1 "$repo" "$name" 2>&1 | while read line; do echo "[GIT] $line"; done; then
      if [ -d "$name" ]; then
        SUCCESS=$((SUCCESS + 1))
        echo "✓ $name cloned successfully"
        echo "Size: $(du -sh "$name" | cut -f1)"
      else
        FAILED=$((FAILED + 1))
        echo "✗ $name directory not found after clone"
      fi
    else
      FAILED=$((FAILED + 1))
      echo "✗ $name clone failed or timed out"
    fi
  fi
  
  echo "Completed: $(date '+%H:%M:%S')"
  echo "Status: $SUCCESS successful, $FAILED failed"
  echo "Remaining: $(( TOTAL - CURRENT )) repositories"
  echo "================================================================"
done

echo ""
echo "GIT REPOSITORIES CLONING SUMMARY:"
echo "================================="
echo "Total attempted: $TOTAL"
echo "Successful: $SUCCESS"
echo "Failed: $FAILED"
echo "Success rate: $(( SUCCESS * 100 / TOTAL ))%"
echo ""
echo "Cloned repositories:"
ls -la "$OPERATOR_DIR/tools/git/" | head -20

exit 0
