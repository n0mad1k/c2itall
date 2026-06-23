#!/bin/bash
# Attack Box - Go Tools Installation Script
# Installs security tools via go install with enhanced feedback

# Get OPERATOR_DIR from environment or use default
OPERATOR_DIR="${OPERATOR_DIR:-/root/operator}"

export GOPATH="$OPERATOR_DIR/tools/go"
export PATH="/root/.local/bin:/usr/local/go/bin:$GOPATH/bin:$PATH"
mkdir -p "$GOPATH"

echo "================================================================"
echo "GO TOOLS INSTALLATION STARTED"
echo "================================================================"
echo "Installing Go tools to $GOPATH/bin..."
echo "Each tool has a 5-minute timeout"
echo "================================================================"

GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/tomnomnom/httprobe@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/ropnop/kerbrute@latest"
)

TOOL_NAMES=(
  "subfinder"
  "httpx"
  "nuclei"
  "naabu"
  "dnsx"
  "katana"
  "waybackurls"
  "assetfinder"
  "httprobe"
  "gf"
  "gau"
  "hakrawler"
  "kerbrute"
)

TOTAL=${#GO_TOOLS[@]}
CURRENT=0
FAILED=0
SUCCESS=0

for i in "${!GO_TOOLS[@]}"; do
  CURRENT=$((CURRENT + 1))
  tool="${GO_TOOLS[$i]}"
  name="${TOOL_NAMES[$i]}"
  
  echo ""
  echo "[$CURRENT/$TOTAL] Installing $name..."
  echo "Repository: $tool"
  echo "Progress: $(( CURRENT * 100 / TOTAL ))%"
  echo "Started: $(date '+%H:%M:%S')"
  echo "Working directory: $GOPATH"
  
  if timeout 300 bash -c "go install -v $tool 2>&1 | while read line; do echo '[GO] $line'; done"; then
    if [ -f "$GOPATH/bin/$name" ]; then
      SUCCESS=$((SUCCESS + 1))
      echo "✓ $name installed successfully at $GOPATH/bin/$name"
      ls -la "$GOPATH/bin/$name"
    else
      FAILED=$((FAILED + 1))
      echo "✗ $name binary not found after installation"
    fi
  else
    FAILED=$((FAILED + 1))
    echo "✗ $name installation failed or timed out"
  fi
  
  echo "Completed: $(date '+%H:%M:%S')"
  echo "Status: $SUCCESS successful, $FAILED failed"
  echo "Remaining: $(( TOTAL - CURRENT )) tools"
  echo "================================================================"
done

echo ""
echo "GO TOOLS INSTALLATION SUMMARY:"
echo "=============================="
echo "Total attempted: $TOTAL"
echo "Successful: $SUCCESS"
echo "Failed: $FAILED"
echo "Success rate: $(( SUCCESS * 100 / TOTAL ))%"
echo ""
echo "Installed Go tools:"
ls -la "$GOPATH/bin/" || echo "No Go tools installed"
echo ""
echo "Go environment:"
echo "GOPATH: $GOPATH"
echo "Go version: $(go version 2>/dev/null || echo 'Go not found')"
echo "Go executable: $(which go || echo 'Go not in PATH')"

exit 0
