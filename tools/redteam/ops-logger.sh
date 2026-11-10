#!/usr/bin/env bash
# OpsLogger - Complete logging solution for red team operations
# Version 2.7.0 - Independent transcripts and explicit command boundaries

# Configuration variables
CONFIG_FILE="${HOME}/.ops-logger.conf"
DEFAULT_TARGET="target-$(hostname | tr '.' '-')"
DEFAULT_LOG_DIR="${HOME}/OperationLogs"
PROMPT_NEW_SHELLS=true
DEBUG=false

# Runtime directory (per-user, mode 700 - defeats pre-created symlink attacks in shared /tmp)
OPS_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}/ops-logger-$(id -u)"

# File markers
LOG_MARKER="${OPS_RUNTIME_DIR}/ops-logger-active"
RECORDING_MARKER="${OPS_RUNTIME_DIR}/ops-logger-recording"
CONFIG_IN_PROGRESS="${OPS_RUNTIME_DIR}/ops-logger-configuring"

shell_quote() {
    local value=${1//\'/\'\\\'\'}
    printf "'%s'" "$value"
}

# Helper functions
log_debug() {
    if [[ "$DEBUG" == "true" ]]; then
        local debug_dir="${LOG_DIR:-${DEFAULT_LOG_DIR}}"
        mkdir -p "$debug_dir" 2>/dev/null
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG: $*" >> "${debug_dir}/ops-logger-debug.log"
    fi
}

ensure_dir() {
    mkdir -p "$1" 2>/dev/null || { echo "Error: failed to create directory '$1' (check that the parent path exists and is writable)" >&2; return 1; }
    if [[ -n "$2" ]]; then
        chmod "$2" "$1" 2>/dev/null
        local owner mode
        read -r owner mode < <(stat -c '%u %a' "$1" 2>/dev/null)
        if [[ "$owner" != "$(id -u)" || "$mode" != "$2" ]]; then
            echo "Error: '$1' is not owned by uid $(id -u) with mode $2 (possibly pre-created by another user)" >&2
            return 1
        fi
    fi
    return 0
}

ensure_dir "$OPS_RUNTIME_DIR" 700 || exit 1

# Shared create_config validation - used by both the tmux and manual prompt
# branches (exported so the tmux branch's separate config_script process can
# call it too) so the two branches can never drift out of sync.
validate_target_name() {
    local name="${1:-$DEFAULT_TARGET}"
    name="$(tr -cd 'A-Za-z0-9._-' <<<"$name")"
    printf '%s' "${name:-$DEFAULT_TARGET}"
}

validate_log_dir() {
    case "$1" in
        *"'"*|*'"'*|*'`'*|*'$'*|*';'*|*'|'*|*'&'*|*$'\n'*) return 1 ;;
        *) return 0 ;;
    esac
}

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        TARGET_NAME="$DEFAULT_TARGET"
        LOG_DIR="$DEFAULT_LOG_DIR"
    fi
    
    TARGET_NAME=$(validate_target_name "${TARGET_NAME:-$DEFAULT_TARGET}")
    LOG_DIR="${LOG_DIR:-$DEFAULT_LOG_DIR}"
    validate_log_dir "$LOG_DIR" || { printf 'ERROR: unsupported log directory characters\n' >&2; return 1; }
    [[ $LOG_DIR == /* ]] || LOG_DIR="$PWD/$LOG_DIR"
}

save_config() {
    ensure_dir "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" << EOF
# Ops Logger Configuration
TARGET_NAME="$TARGET_NAME"
LOG_DIR="$LOG_DIR"
PROMPT_NEW_SHELLS=$PROMPT_NEW_SHELLS
DEBUG=$DEBUG
EOF
}

# Get public IP
get_public_ip() {
    local ip
    ip=$(curl -fsS --connect-timeout 3 --max-time 5 https://ifconfig.me/ip) || \
    ip=$(curl -fsS --connect-timeout 3 --max-time 5 https://ipinfo.io/ip) || \
    ip=$(curl -fsS --connect-timeout 3 --max-time 5 https://icanhazip.com) || \
    ip="unknown"
    echo "$ip"
}

# Detection functions
is_tmux() { [[ -n "$TMUX" ]]; }

# Get normalized pane ID (session-window-pane format)
get_pane_id() {
    if is_tmux; then
        local pane
        pane=$(get_tmux_pane_ref) || return 1
        tmux display-message -p -t "$pane" 'server-#{pid}-pane-#{pane_id}' | tr -d '%'
    else
        printf 'shell-%s\n' "$$"
    fi
}

# Get tmux pane reference for tmux commands (% format for tmux commands)
get_tmux_pane_ref() {
    if is_tmux; then
        # If TMUX_PANE is set (from hook), use that specific pane
        if [[ -n "$TMUX_PANE" ]]; then
            echo "$TMUX_PANE"
        else
            tmux display -p '#{pane_id}'
        fi
    else
        echo ""
    fi
}

# Get the actual tmux prefix key instead of hardcoding C-b
get_tmux_prefix() {
    # First check if we're using oh-my-tmux which often uses C-a
    if tmux show-options -g | grep -q "TMUX_CONF"; then
        # Check if prefix has been overridden in .local config
        local prefix=$(tmux show-options -g prefix 2>/dev/null | awk '{print $2}')
        if [[ -n "$prefix" ]]; then
            case "$prefix" in
                "C-q") echo "C-q" ;;
                "C-a") echo "C-a" ;;
                "C-b") echo "C-b" ;;
                *) echo "$prefix" ;;
            esac
        else
            echo "C-a"  # oh-my-tmux default
        fi
    else
        # Try to get the actual prefix from tmux config
        local prefix=$(tmux show-options -g prefix 2>/dev/null | awk '{print $2}')
        if [[ -n "$prefix" ]]; then
            echo "$prefix"
        else
            # Default to C-b if we can't determine
            echo "C-b"
        fi
    fi
}

logging_run_dir() {
    local run
    IFS= read -r run < "${LOG_MARKER}-$1" 2>/dev/null || return 1
    [[ $run == "$OPS_RUNTIME_DIR/ops-run-"* && -d $run && ! -L $run ]] || return 1
    printf '%s\n' "$run"
}
is_logging_active() {
    local run pid
    run=$(logging_run_dir "$1") || return 1
    [[ -f $run/enabled ]] || return 1
    if is_tmux; then
        [[ $(cat "$run/capture" 2>/dev/null) == running ]] || return 1
        read -r pid < "$run/writer.pid" || return 1
        kill -0 "$pid" 2>/dev/null || return 1
        [[ $(tmux display-message -p -t "$(get_tmux_pane_ref)" '#{pane_pipe}' 2>/dev/null) == 1 ]] || return 1
    fi
}
is_recording_active() { [[ -f "${RECORDING_MARKER}-$1" ]]; }

# ================================================================
# DEPENDENCY CHECKING
# ================================================================

# Check if TPM is installed
check_tpm_installed() {
    [[ -d "$HOME/.tmux/plugins/tpm" ]]
}

# Check if tmux-logging plugin is installed
check_tmux_logging_installed() {
    [[ -d "$HOME/.tmux/plugins/tmux-logging" ]]
}

# Print installation instructions for TMux Plugin Manager (TPM)
print_tpm_install_instructions() {
    echo "========================================================================="
    echo "Tmux Plugin Manager (TPM) is not installed. To install:"
    echo "========================================================================="
    echo "1. Run these commands:"
    echo "   mkdir -p ~/.tmux/plugins"
    echo "   git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm"
    echo ""
    echo "2. Add these lines to your ~/.tmux.conf:"
    echo "   # List of plugins"
    echo "   set -g @plugin 'tmux-plugins/tpm'"
    echo "   set -g @plugin 'tmux-plugins/tmux-sensible'"
    echo "   set -g @plugin 'tmux-plugins/tmux-logging'"
    echo ""
    echo "   # Initialize TMUX plugin manager (keep this line at the bottom)"
    echo "   run '~/.tmux/plugins/tpm/tpm'"
    echo ""
    echo "3. Reload your tmux configuration:"
    echo "   tmux source-file ~/.tmux.conf"
    echo ""
    echo "4. Install plugins by pressing:"
    echo "   prefix + I (capital I)"
    echo "========================================================================="
}

# Print installation instructions for tmux-logging plugin
print_tmux_logging_install_instructions() {
    echo "========================================================================="
    echo "tmux-logging plugin is not installed. To install:"
    echo "========================================================================="
    echo "1. Ensure TPM is installed (see previous instructions if needed)"
    echo ""
    echo "2. Add this line to your ~/.tmux.conf (before the tpm init line):"
    echo "   set -g @plugin 'tmux-plugins/tmux-logging'"
    echo ""
    echo "3. Reload your tmux configuration:"
    echo "   tmux source-file ~/.tmux.conf"
    echo ""
    echo "4. Install the plugin by pressing:"
    echo "   prefix + I (capital I)"
    echo "========================================================================="
}

# Check for required dependencies
check_dependencies() {
    local id="$1"
    local missing=false
    
    if ! is_tmux; then
        echo "WARNING: Not running in tmux. Only basic CSV logging will be available."
        echo "         For full functionality, start tmux first."
        return 0
    fi
    
    # Check TPM and tmux-logging plugin
    if ! check_tpm_installed; then
        missing=true
        print_tpm_install_instructions
    elif ! check_tmux_logging_installed; then
        missing=true
        print_tmux_logging_install_instructions
    fi
    
    if $missing; then
        # Don't use display-message, just echo
        echo "Plugin dependencies missing, see instructions above"
        return 1
    fi
    
    return 0
}

# ================================================================
# CSV LOGGING (our custom implementation)
# ================================================================

# Setup CSV logging (ORIGINAL FORMAT MAINTAINED)
setup_csv_log() {
    local target=$1 log_dir=$2 csv_file="$2/$1_commands.csv"
    ensure_dir "$log_dir" 700 || return 1
    (
        umask 077
        flock -x 8 || exit 1
        if [[ ! -s $csv_file ]]; then
            printf '%s\n' '"StartTime","EndTime","SourceIP","User","Path","Command"' >&8 || exit 1
        fi
    ) 8>> "$csv_file" || return 1
    chmod 600 "$csv_file" || return 1
    printf '%s\n' "$csv_file"
}

# ================================================================
# UNIFIED VERBOSE LOGGING WITH COMMAND HEADERS
# ================================================================

csv_record_count() {
    flock -s "$1" awk '
        BEGIN { quoted=0; records=0 }
        {
            for (i=1; i<=length($0); i++) {
                if (substr($0,i,1)=="\"") {
                    if (quoted && substr($0,i+1,1)=="\"") i++
                    else quoted=!quoted
                }
            }
            if (!quoted) records++
        }
        END { print (records>0 ? records-1 : 0) }
    ' "$1"
}

# Create single master verbose log file for all panes
create_master_verbose_log() {
    local target=$1 log_dir=$2 verbose_dir="$2/verbose" log_file="$2/verbose/$1_master.log"
    ensure_dir "$verbose_dir" 700 || return 1
    (
        umask 077
        flock -x 8 || exit 1
        if [[ ! -s $log_file ]]; then
            printf 'RED TEAM TERMINAL LOGGER\nTarget: %s\nHost: %s\nStarted: %s\n\n' \
                "$target" "$(hostname)" "$(date '+%Y-%m-%d %H:%M:%S')" >&8 || exit 1
        fi
    ) 8>> "$log_file" || return 1
    chmod 600 "$log_file" || return 1
    printf '%s\n' "$log_file"
}

# Create debug filter that captures EVERYTHING (no filtering)
create_debug_filter_script() {
    local filter_script
    filter_script=$(mktemp "${OPS_RUNTIME_DIR}/ops-debug-filter-XXXXXX.sh") || { echo "ERROR: failed to create debug filter script" >&2; return 1; }

    cat > "$filter_script" << 'EODEBUG'
#!/usr/bin/env bash
# DEBUG: Raw pipe-pane output capture

LOGFILE="$1"
PANE_ID="$2"
DEBUG_RAW_FILE="${LOGFILE}.debug-raw"

mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null

echo "[$(date)] DEBUG FILTER STARTED for pane $PANE_ID" >> "$DEBUG_RAW_FILE"
echo "=================================================" >> "$DEBUG_RAW_FILE"

line_count=0
while IFS= read -r line; do
    line_count=$((line_count + 1))
    
    # Write EVERYTHING to debug file with line numbers
    printf "[%04d][$(date +%H:%M:%S)] RAW: %s\n" "$line_count" "$line" >> "$DEBUG_RAW_FILE"
    
    # Also write to main log (no filtering at all)
    echo "$line" >> "$LOGFILE"
done

echo "[$(date)] DEBUG FILTER ENDED - Total lines: $line_count" >> "$DEBUG_RAW_FILE"
EODEBUG
    
    chmod +x "$filter_script"
    echo "$filter_script"
}

# Add debug start function
start_debug_verbose_logging() {
    local id="$1"
    local tmux_pane_ref="$2"
    local target="$3"
    local log_dir="$4"
    
    if [[ $(tmux display-message -p -t "$tmux_pane_ref" '#{pane_pipe}') == 1 ]]; then
        printf 'ERROR: stop the existing pane capture before enabling debug capture\n' >&2
        return 1
    fi
    local debug_log="${log_dir}/debug-${target}-${id}-$(date +%H%M%S).log"
    local filter_script=$(create_debug_filter_script)
    
    echo "Starting DEBUG verbose logging to: $debug_log"
    
    # Use simple pipe-pane with debug filter
    tmux pipe-pane -t "$tmux_pane_ref" "bash '$filter_script' '$debug_log' '$id'"
    
    sleep 1
    
    # Check if logging started
    if [[ $(tmux display-message -p -t "$tmux_pane_ref" '#{pane_pipe}') == 1 ]]; then
        echo "DEBUG logging started successfully"
        echo "Raw output file: ${debug_log}.debug-raw"
        echo "Filtered output file: $debug_log"
        
        echo "$filter_script" > "${OPS_RUNTIME_DIR}/ops-debug-filter-script-${id}"
        return 0
    else
        echo "ERROR: DEBUG logging failed to start"
        rm -f "$filter_script"
        return 1
    fi
}

# Generate a summary reader. Raw capture is a separate, direct file writer.
create_verbose_filter_script() {
    local filter_script
    filter_script=$(mktemp "${OPS_RUNTIME_DIR}/ops-verbose-filter-XXXXXX.sh") || return 1
    cat > "$filter_script" << 'EOFILTER'
#!/usr/bin/env bash
set -o pipefail
LOGFILE=$1 PANE_ID=$2 TARGET=$3 RUN_DIR=$4
TOKEN=${RUN_DIR##*/}
PREFIX=$'\033]777;ops-logger;'"$TOKEN;"
IN_COMMAND=false
OUTPUT_LINE_COUNT=0
MAX_LINES_PER_COMMAND=22
exec 9>> "$LOGFILE" || exit 1
write_log() {
    flock 9 || return 1
    printf '%s\n' "$@" >&9
    local rc=$?
    flock -u 9 || return 1
    return "$rc"
}
close_current_command() {
    if [[ $IN_COMMAND == true ]]; then
        write_log "[$PANE_ID] ==============================================================================" || exit 1
    fi
    IN_COMMAND=false
    OUTPUT_LINE_COUNT=0
}
open_command() {
    local event=$1 cmd start_time user path public_ip pane_marker
    [[ $event =~ ^[a-zA-Z0-9]+$ ]] || return 0
    local file="$RUN_DIR/events/$event"
    [[ -f $file && ! -L $file ]] || return 0
    {
        IFS= read -r -d '' cmd && IFS= read -r -d '' start_time &&
        IFS= read -r -d '' user && IFS= read -r -d '' path &&
        IFS= read -r -d '' public_ip && IFS= read -r -d '' pane_marker
    } < "$file" || return 1
    [[ $pane_marker == "$PANE_ID" ]] || return 1
    close_current_command
    # Each header is one locked write; each output line also identifies its pane.
    write_log "[$PANE_ID] ==============================================================================" \
        "[$PANE_ID] Command: $cmd" "[$PANE_ID] Start: $start_time" \
        "[$PANE_ID] User: $user  Path: $path  Public IP: $public_ip" \
        "[$PANE_ID] OUTPUT:" || return 1
    IN_COMMAND=true
    rm -f -- "$file"
}
log_output() {
    local line=$1 clean_line
    [[ -n $line ]] || return 0
    # This is a short readable summary, not a terminal emulator. Raw bytes are
    # already written to the independent transcript before this reader sees them.
    if [[ $IN_COMMAND == false ]]; then
        write_log "[$PANE_ID] Unattributed pane output:" || return 1
        IN_COMMAND=true
    fi
    ((OUTPUT_LINE_COUNT+=1))
    if (( OUTPUT_LINE_COUNT <= MAX_LINES_PER_COMMAND )); then
        clean_line=$(printf '%s' "$line" | sed -E 's/\x1b\[[0-?]*[ -\/]*[@-~]//g') || return 1
        printf -v stamp '%(%H:%M:%S)T' -1
        write_log "$stamp [$PANE_ID] $clean_line" || return 1
    elif (( OUTPUT_LINE_COUNT == MAX_LINES_PER_COMMAND + 1 )); then
        write_log "[$PANE_ID] ... [OUTPUT TRUNCATED - showing first $MAX_LINES_PER_COMMAND lines only; full output in transcript] ..." || return 1
    fi
}
# Markers are in the same PTY byte stream as output. Metadata is NUL-delimited
# and immutable per event, so pipes/newlines and rapid commands cannot replace it.
while IFS= read -r line || [[ -n $line ]]; do
    while [[ $line == *"$PREFIX"* ]]; do
        before=${line%%"$PREFIX"*}
        rest=${line#*"$PREFIX"}
        if [[ $rest != *$'\a'* ]]; then
            break
        fi
        event=${rest%%$'\a'*}
        log_output "$before" || exit 1
        open_command "$event" || exit 1
        line=${rest#*$'\a'}
    done
    log_output "$line" || exit 1
done
close_current_command
EOFILTER
    chmod 700 "$filter_script" || return 1
    printf '%s\n' "$filter_script"
}

# The collector never pipes pane bytes through the summary reader. A slow or
# failed summary can neither block cat nor discard its unmodified transcript.
create_capture_script() {
    local script
    script=$(mktemp "${OPS_RUNTIME_DIR}/ops-capture-XXXXXX.sh") || return 1
    cat > "$script" << 'EOCAPTURE'
#!/usr/bin/env bash
set -o pipefail
run=$1 raw=$2 master=$3 pane=$4 target=$5 filter=$6
socket=${7:-} tmux_pane=${8:-}
umask 077
state() { printf '%s\n' "$2" > "$run/$1.tmp" && mv -f "$run/$1.tmp" "$run/$1"; }
notify_failure() {
    [[ -n $socket && -n $tmux_pane ]] || return 0
    tmux -S "$socket" display-message -t "$tmux_pane" "ops-logger: $1" 2>/dev/null || true
}
exec 3>> "$raw" || { state capture failed; notify_failure 'cannot open transcript'; exit 1; }
exec 4<&0
cat <&4 >&3 &
writer=$!
printf '%s\n' "$writer" > "$run/writer.pid"
state summary running
(
    tail --pid="$writer" -s 0.1 -c +1 -f -- "$raw" | bash "$filter" "$master" "$pane" "$target" "$run"
    rc=$?
    if (( rc )); then state summary failed; notify_failure 'summary failed; transcript capture continues'; else state summary stopped; fi
    exit "$rc"
) 3>&- 4<&- &
summary=$!
state capture running
printf '%s\n' "$$" > "$run/collector.pid"
: > "$run/ready"
wait "$writer"
rc=$?
if (( rc )); then state capture failed; notify_failure 'transcript write failed; capture stopped'; else state capture stopped; fi
exec 3>&- 4<&-
wait "$summary"
summary_rc=$?
state done "$rc $summary_rc"
exit "$((rc || summary_rc))"
EOCAPTURE
    chmod 700 "$script" || return 1
    printf '%s\n' "$script"
}

create_enhanced_command_hook() {
    local hook_script=$1 csv_log=$2 pane_id=$3 verbose_log=$4 run_dir=$5
    {
        printf 'CSV_LOG=%q\nVERBOSE_LOG=%q\nPANE_ID=%q\nRTL_RUN_DIR=%q\n' "$csv_log" "$verbose_log" "$pane_id" "$run_dir"
        # Preserve state across re-sourcing into the same shell.
        cat << 'EOHOOK'
RTL_ENABLE_FILE="$RTL_RUN_DIR/enabled"
RTL_INTERNAL_LOGGING=true
RTL_CMD_START_TIME=""
RTL_COMMAND_PENDING=false
RTL_IN_PROMPT=false
PUBLIC_IP=$(timeout 5 curl -fsS --max-time 4 https://ifconfig.me/ip 2>/dev/null || printf unknown)
should_log_command() {
    case "$1" in
        *RTL_*|*CSV_LOG*|*PROMPT_COMMAND*|*ops-hook-*|'') return 1 ;;
        *) return 0 ;;
    esac
}
write_verbose_header() {
    [[ -n $VERBOSE_LOG && -f $RTL_ENABLE_FILE ]] || return 0
    local file event
    file=$(mktemp "$RTL_RUN_DIR/events/XXXXXXXXXXXX") || return 1
    event=${file##*/}
    printf '%s\0' "$1" "$2" "$(whoami)" "$PWD" "$PUBLIC_IP" "$PANE_ID" > "$file" || return 1
    # Use the controlling terminal, not a command's redirected stdout. The
    # ignored OSC carries only an event id; metadata stays in private files.
    printf '\033]777;ops-logger;%s;%s\a' "${RTL_RUN_DIR##*/}" "$event" > /dev/tty || return 1
}
RTL_log_command() {
    local cmd=$1 start=$2 end=$3 field row="" sep="" escaped
    [[ -f $RTL_ENABLE_FILE ]] || return 0
    should_log_command "$cmd" || return 0
    case "$cmd" in [-+=@]*) cmd="'$cmd" ;; esac
    for field in "$start" "$end" "$PUBLIC_IP" "$(whoami)" "${RTL_COMMAND_PATH:-$PWD}" "$cmd"; do
        escaped=${field//\"/\"\"}
        row+="$sep\"$escaped\""
        sep=,
    done
    # Lock one complete CSV record, including embedded newlines.
    if ! ( flock -x 8 && printf '%s\n' "$row" >&8 ) 8>> "$CSV_LOG"; then
        printf 'failed\n' > "$RTL_RUN_DIR/csv"
        printf 'ops-logger: CSV write failed: %s\n' "$CSV_LOG" >&2
        return 1
    fi
}
if [[ -n ${BASH_VERSION:-} ]]; then
    if [[ ${RTL_HOOK_INSTALLED:-false} != true ]]; then
        RTL_ORIG_PROMPT_DECL=$(declare -p PROMPT_COMMAND 2>/dev/null || true)
        RTL_ORIG_DEBUG_TRAP=${RTL_INSTALL_DEBUG_TRAP:-$(trap -p DEBUG)}
        unset RTL_INSTALL_DEBUG_TRAP
        RTL_ORIG_PROMPTS=("${PROMPT_COMMAND[@]}")
    fi
    RTL_HOOK_INSTALLED=true
    RTL_preexec() {
        [[ -f $RTL_ENABLE_FILE && $RTL_IN_PROMPT == false ]] || return 0
        local cmd=$BASH_COMMAND
        should_log_command "$cmd" || return 0
        # One boundary for the entered shell command, not every simple command
        # in a pipeline or the logger's own prompt plumbing.
        [[ $RTL_COMMAND_PENDING == false ]] || return 0
        RTL_COMMAND_PENDING=true
        RTL_COMMAND_PATH=$PWD
        RTL_CURRENT_COMMAND=$cmd
        local entry number history_cmd
        entry=$(HISTTIMEFORMAT= history 1)
        if [[ $entry =~ ^[[:space:]]*([0-9]+)[[:space:]]+(.*)$ ]]; then
            number=${BASH_REMATCH[1]}
            history_cmd=${BASH_REMATCH[2]}
            if [[ $number != "${RTL_PREVIOUS_HISTNUM:-}" || $history_cmd == "$cmd" ]]; then
                RTL_CURRENT_COMMAND=$history_cmd
            fi
            RTL_PREVIOUS_HISTNUM=$number
        fi
        printf -v RTL_CMD_START_TIME '%(%Y-%m-%d %H:%M:%S)T' -1
        write_verbose_header "$RTL_CURRENT_COMMAND" "$RTL_CMD_START_TIME"
    }
    RTL_PROMPT_COMMAND() {
        local current_cmd end_time
        if [[ $RTL_COMMAND_PENDING == true && -f $RTL_ENABLE_FILE ]]; then
            # Execution identity is the preexec/prompt cycle, not history text
            # or HISTCONTROL's possibly deduplicated history number.
            current_cmd=$RTL_CURRENT_COMMAND
            printf -v end_time '%(%Y-%m-%d %H:%M:%S)T' -1
            RTL_log_command "$current_cmd" "$RTL_CMD_START_TIME" "$end_time"
        fi
        RTL_COMMAND_PENDING=false
        RTL_CMD_START_TIME=""
    }
    # Cleanup runs as top-level PROMPT_COMMAND code, never injected into a
    # foreground program. Restoring DEBUG inside a function would be temporary.
    RTL_PROMPT_DISPATCH='RTL_PROMPT_STATUS=$?; RTL_IN_PROMPT=true; if [[ -f "$RTL_ENABLE_FILE" ]]; then RTL_PROMPT_COMMAND; else trap - DEBUG; [[ -z "$RTL_ORIG_DEBUG_TRAP" ]] || eval "$RTL_ORIG_DEBUG_TRAP"; unset PROMPT_COMMAND; [[ -z "$RTL_ORIG_PROMPT_DECL" ]] || eval "$RTL_ORIG_PROMPT_DECL"; RTL_HOOK_INSTALLED=false; fi; (exit "$RTL_PROMPT_STATUS")'
    PROMPT_COMMAND=("$RTL_PROMPT_DISPATCH" "${RTL_ORIG_PROMPTS[@]}" 'RTL_IN_PROMPT=false; (exit "$RTL_PROMPT_STATUS")') || return 1
    trap 'RTL_preexec' DEBUG || return 1
elif [[ -n ${ZSH_VERSION:-} ]]; then
    RTL_zsh_preexec() {
        [[ -f $RTL_ENABLE_FILE ]] || return 0
        RTL_COMMAND_PENDING=true
        RTL_COMMAND_PATH=$PWD
        RTL_CMD_START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
        write_verbose_header "$1" "$RTL_CMD_START_TIME"
    }
    RTL_zsh_precmd() {
        if [[ ! -f $RTL_ENABLE_FILE ]]; then
            add-zsh-hook -d preexec RTL_zsh_preexec
            add-zsh-hook -d precmd RTL_zsh_precmd
        elif [[ $RTL_COMMAND_PENDING == true ]]; then
            RTL_log_command "$(fc -ln -1)" "$RTL_CMD_START_TIME" "$(date '+%Y-%m-%d %H:%M:%S')"
        fi
        RTL_COMMAND_PENDING=false
    }
    autoload -Uz add-zsh-hook
    add-zsh-hook -d preexec RTL_zsh_preexec 2>/dev/null
    add-zsh-hook -d precmd RTL_zsh_precmd 2>/dev/null
    add-zsh-hook preexec RTL_zsh_preexec
    add-zsh-hook precmd RTL_zsh_precmd
else
    printf 'ops-logger: unsupported shell\n' >&2
    return 1
fi
: > "$RTL_RUN_DIR/hook-ready"
EOHOOK
    } > "$hook_script" || return 1
    chmod 700 "$hook_script"
}

start_unified_verbose_logging() {
    local id=$1 tmux_pane_ref=$2 target=$3 log_dir=$4 run_dir=$5
    local master_log filter_script collector raw command i
    [[ $(tmux display-message -p -t "$tmux_pane_ref" '#{pane_pipe}') == 0 ]] || {
        printf 'ERROR: pane already has an output pipe; refusing to replace it\n' >&2; return 1;
    }
    master_log=$(create_master_verbose_log "$target" "$log_dir") || return 1
    ensure_dir "$log_dir/transcripts" 700 || return 1
    raw=$(mktemp "$log_dir/transcripts/${target}_${id}_$(date +%Y%m%d_%H%M%S)_XXXXXX.terminal.log") || return 1
    chmod 600 "$raw" || return 1
    printf '%s\n' "$raw" > "$run_dir/transcript"
    filter_script=$(create_verbose_filter_script) || return 1
    collector=$(create_capture_script) || return 1
    printf '%s\n' "$filter_script" "$collector" > "$run_dir/helpers"
    # Paths are shell-quoted for tmux's sh -c (not Bash-specific %q).
    command=bash
    local arg
    for arg in "$collector" "$run_dir" "$raw" "$master_log" "$id" "$target" "$filter_script" "$(tmux display-message -p -t "$tmux_pane_ref" '#{socket_path}')" "$tmux_pane_ref"; do
        command+=" $(shell_quote "$arg")"
    done
    tmux pipe-pane -t "$tmux_pane_ref" "$command" || return 1
    for ((i=0; i<100; i++)); do
        [[ -f $run_dir/ready ]] && break
        sleep 0.05
    done
    if [[ ! -f $run_dir/ready ]] || [[ $(cat "$run_dir/capture" 2>/dev/null) != running ]] ||
       [[ $(tmux display-message -p -t "$tmux_pane_ref" '#{pane_pipe}') != 1 ]]; then
        tmux pipe-pane -t "$tmux_pane_ref"
        printf 'ERROR: transcript writer failed to start\n' >&2
        return 1
    fi
}

stop_unified_verbose_logging() {
    local tmux_pane_ref=$1 id=$2 run_dir=$3 i previous="" current
    [[ -d $run_dir ]] || return 0
    # Allow an idle pane's already received bytes to settle before disconnect.
    # A continuously producing pane still has an explicit bounded stop point.
    for ((i=0; i<10; i++)); do
        current=$(stat -c %s -- "$(cat "$run_dir/transcript")" 2>/dev/null)
        [[ $current == "$previous" ]] && break
        previous=$current
        sleep 0.1
    done
    if [[ $(cat "$run/capture" 2>/dev/null) == running ]]; then
        tmux pipe-pane -t "$tmux_pane_ref" || return 1
    fi
    for ((i=0; i<100; i++)); do
        [[ -f $run_dir/done ]] && break
        sleep 0.05
    done
    if [[ ! -f $run_dir/done || $(cat "$run_dir/done") != '0 0' ]]; then
        printf 'ERROR: capture/summary did not finish cleanly; evidence retained in %s\n' "$run_dir" >&2
        return 1
    fi
    while IFS= read -r helper; do
        [[ $helper == "$OPS_RUNTIME_DIR/ops-"*.sh ]] && rm -f -- "$helper"
    done < "$run_dir/helpers"
}

# ================================================================
# OHMYTMUX-COMPATIBLE WINDOW NAME MANAGEMENT
# ================================================================

# Improved window name handling that works with ohmytmux
get_current_window_name() {
    local tmux_pane_ref="$1"
    local name=$(tmux display -t "$tmux_pane_ref" -p '#{window_name}')
    
    # Remove our indicators as well as any ohmytmux status indicators
    name="${name#🔴 }"
    name="${name#🎥 }"
    name="${name#● }"
    name="${name#⚠ }"
    name="${name#▶ }"
    
    echo "$name"
}

set_window_logging_indicator() {
    local tmux_pane_ref="$1"
    local current_name=$(get_current_window_name "$tmux_pane_ref")
    
    # Preserve ohmytmux automatic formats but add our indicator
    if [[ "$current_name" == *Z ]]; then
        # Zoomed window format in ohmytmux
        tmux rename-window -t "$tmux_pane_ref" "🔴 ${current_name%Z}Z"
    else
        tmux rename-window -t "$tmux_pane_ref" "🔴 $current_name"
    fi
}

set_window_recording_indicator() {
    local tmux_pane_ref="$1"
    local current_name=$(get_current_window_name "$tmux_pane_ref")
    
    # Remove logging indicator if present and add recording
    current_name="${current_name#🔴 }"
    
    # Preserve ohmytmux automatic formats
    if [[ "$current_name" == *Z ]]; then
        # Zoomed window format in ohmytmux
        tmux rename-window -t "$tmux_pane_ref" "🎥 ${current_name%Z}Z"
    else
        tmux rename-window -t "$tmux_pane_ref" "🎥 $current_name"
    fi
}

clear_window_indicators() {
    local tmux_pane_ref="$1"
    local current_name=$(tmux display -t "$tmux_pane_ref" -p '#{window_name}')
    local clean_name=$(get_current_window_name "$tmux_pane_ref")
    
    # Preserve any ohmytmux indicators that might be present
    if [[ "$current_name" == *Z ]]; then
        # Zoomed window format in ohmytmux
        tmux rename-window -t "$tmux_pane_ref" "${clean_name}Z"
    else
        tmux rename-window -t "$tmux_pane_ref" "$clean_name"
    fi
}

# MAIN LOGGING FUNCTIONS
# ================================================================

# Enhanced logging installation with unified verbose logging
install_logging() {
    local id=$1 csv_log=$2 target=$3 log_dir=$4
    local run hook pane current i command arg master=""
    run=$(mktemp -d "$OPS_RUNTIME_DIR/ops-run-XXXXXXXXXXXX") || return 1
    mkdir -m 700 "$run/events" || return 1
    hook="$run/ops-hook.sh"
    if is_tmux; then
        pane=$(get_tmux_pane_ref) || return 1
        start_unified_verbose_logging "$id" "$pane" "$target" "$log_dir" "$run" || return 1
        master="$log_dir/verbose/${target}_master.log"
    elif [[ ${BASH_SOURCE[0]} == "$0" ]]; then
        printf 'ERROR: direct-shell logging must be enabled in the caller: source ops-logger.sh; start_operation_log -AutoStart\n' >&2
        return 1
    fi
    : > "$run/enabled"
    printf '%s\n' "$run" > "${LOG_MARKER}-${id}"
    create_enhanced_command_hook "$hook" "$csv_log" "$id" "$master" "$run" || {
        rm -f "$run/enabled"
        is_tmux && stop_unified_verbose_logging "$pane" "$id" "$run"
        return 1
    }
    if is_tmux; then
        current=$(tmux display-message -p -t "$pane" '#{pane_current_command}')
        case "$current" in
            bash|zsh|-bash|-zsh)
                # Enter is separate: send-keys must not interpret path text as
                # key names. Enable from an empty local shell prompt.
                printf -v command 'RTL_INSTALL_DEBUG_TRAP=$(trap -p DEBUG); source %q' "$hook"
                tmux send-keys -t "$pane" -l "$command"
                tmux send-keys -t "$pane" Enter
                # A CLI started by this pane's shell must return before the
                # queued source command can run. Capture is already verified;
                # status reports hooks pending until their own acknowledgment.
                if [[ $PPID == "$(tmux display-message -p -t "$pane" '#{pane_pid}')" ]]; then
                    printf 'Transcript active; shell hooks will attach when this command returns.\n'
                else
                for ((i=0; i<140; i++)); do
                    [[ -f $run/hook-ready ]] && break
                    sleep 0.05
                done
                if [[ ! -f $run/hook-ready ]]; then
                    rm -f "$run/enabled"
                    stop_unified_verbose_logging "$pane" "$id" "$run"
                    printf 'ERROR: shell hook did not acknowledge installation; logging stopped\n' >&2
                    return 1
                fi
                fi
                ;;
            *)
                # Starting inside a child console is useful for output capture,
                # but shell code must never be sent to that program's input.
                printf 'Transcript active; shell CSV hooks unavailable until logging is restarted at a local shell prompt.\n'
                ;;
        esac
        if ! is_logging_active "$id"; then
            printf 'ERROR: transcript writer failed during startup\n' >&2
            rm -f "$run/enabled"
            return 1
        fi
        set_window_logging_indicator "$pane"
        printf 'Transcript: %s\n' "$(cat "$run/transcript")"
    else
        source "$hook" || return 1
        printf 'Direct shell CSV logging active\n'
    fi
}

remove_logging() {
    local id=$1 run rc=0
    run=$(logging_run_dir "$id") || return 0
    # The installed hooks observe this flag and restore the original shell
    # prompt/trap when the local shell next resumes. No send-keys on stop.
    rm -f "$run/enabled"
    if is_tmux; then
        stop_unified_verbose_logging "$(get_tmux_pane_ref)" "$id" "$run" || rc=$?
        clear_window_indicators "$(get_tmux_pane_ref)"
    fi
    if (( rc == 0 )); then
        rm -f "${LOG_MARKER}-${id}" "${LOG_MARKER}-${id}.success"
    fi
    return "$rc"
}

# ================================================================
# RECORDING FUNCTIONS
# ================================================================

start_recording() {
    local id="$1"
    local target="$2"
    local log_dir="$3"
    local recordings_dir="${log_dir}/recordings"
    local timestamp=$(date +%Y%m%d_%H%M%S)

    ensure_dir "$recordings_dir" 700
    
    # Check for asciinema
    if ! command -v asciinema >/dev/null 2>&1; then
        local error_msg="ERROR: asciinema not installed"
        echo "$error_msg" >&2
        echo "To install asciinema:"
        echo "  Ubuntu/Debian: sudo apt install asciinema"
        echo "  Fedora/RHEL: sudo dnf install asciinema"
        echo "  macOS: brew install asciinema"
        echo "  Pip: pip3 install asciinema"
        return 1
    fi
    
    local cast_file="${recordings_dir}/${target}_${id}_${timestamp}.cast"
    echo "asciinema:$cast_file" > "${RECORDING_MARKER}-${id}"
    
    if is_tmux; then
        local tmux_pane_ref=$(get_tmux_pane_ref)
        
        # Set recording indicator (ohmytmux compatible)
        set_window_recording_indicator "$tmux_pane_ref"
        
        # Start recording cleanly
        tmux send-keys -t "$tmux_pane_ref" "asciinema rec '$cast_file'" ENTER
        
    else
        echo "Starting asciinema recording. Use 'exit' or Ctrl+D to stop."
        asciinema rec "$cast_file"
    fi
}

stop_recording() {
    local id="$1"
    
    [[ ! -f "${RECORDING_MARKER}-${id}" ]] && {
        echo "No active recording"
        return 1
    }
    
    read -r rec_type rec_path < <(cat "${RECORDING_MARKER}-${id}" | tr ':' ' ')
    
    if [[ "$rec_type" == "asciinema" ]]; then
        if is_tmux; then
            local tmux_pane_ref=$(get_tmux_pane_ref)
            
            # Try sending Ctrl+D
            tmux send-keys -t "$tmux_pane_ref" C-d
            
            sleep 1
            
            # If that didn't work, try killing the asciinema process
            if ps aux | grep -v grep | grep -q "asciinema rec"; then
                log_debug "Ctrl+D didn't stop recording, trying to kill asciinema process"
                tmux send-keys -t "$tmux_pane_ref" "pkill -f 'asciinema rec'" ENTER
                
                sleep 1
                
                if ps aux | grep -v grep | grep -q "asciinema rec"; then
                    pkill -f "asciinema rec" || true
                fi
            fi
            
            # Clear recording indicator but preserve logging indicator
            local current_name=$(tmux display -t "$tmux_pane_ref" -p '#{window_name}')
            if [[ "$current_name" == "🎥"* ]]; then
                if is_logging_active "$id"; then
                    local clean_name="${current_name#🎥 }"
                    tmux rename-window -t "$tmux_pane_ref" "🔴 $clean_name"
                else
                    clear_window_indicators "$tmux_pane_ref"
                fi
            fi
            
        else
            echo "Recording stopped: $rec_path"
        fi
    fi
    
    rm -f "${RECORDING_MARKER}-${id}"
}

# ================================================================
# CONFIGURATION FUNCTIONS
# ================================================================

create_config() {
    local is_first_run="${1:-false}"
    
    # If this is a first run from ensure_config in tmux, use the local version's approach
    if [[ "$is_first_run" == "true" ]] && is_tmux; then
        # Mark configuration as in progress
        touch "$CONFIG_IN_PROGRESS"
        
        # Create a temporary script that will handle the config creation
        local config_script
        config_script=$(mktemp "${OPS_RUNTIME_DIR}/ops-config-XXXXXX.sh") || { echo "Error: failed to create config script."; return 1; }
        cat > "$config_script" << 'EOSCRIPT'
#!/usr/bin/env bash
CONFIG_FILE="${HOME}/.ops-logger.conf"
DEFAULT_TARGET="target-$(hostname | tr '.' '-')"
DEFAULT_LOG_DIR="${HOME}/OperationLogs"

echo "Red Team Terminal Logger - First Time Setup"
echo "==========================================="
echo ""

read -p "Enter target name [$DEFAULT_TARGET]: " TARGET_NAME
TARGET_NAME="$(validate_target_name "$TARGET_NAME")"

read -p "Enter log directory [$DEFAULT_LOG_DIR]: " LOG_DIR
LOG_DIR="${LOG_DIR:-$DEFAULT_LOG_DIR}"
while ! validate_log_dir "$LOG_DIR"; do
    echo "Log directory contains a disallowed character (quote, backtick, dollar sign, semicolon, pipe, or ampersand). Please try again."
    read -p "Enter log directory [$DEFAULT_LOG_DIR]: " LOG_DIR
    LOG_DIR="${LOG_DIR:-$DEFAULT_LOG_DIR}"
done

read -p "Prompt for logging in new shells? [Y/n]: " PROMPT_NEW_SHELLS
[[ "${PROMPT_NEW_SHELLS,,}" == "n" ]] && PROMPT_NEW_SHELLS=false || PROMPT_NEW_SHELLS=true

read -p "Enable debug logging? [y/N]: " DEBUG
[[ "${DEBUG,,}" == "y" ]] && DEBUG=true || DEBUG=false

# Save config
mkdir -p "$(dirname "$CONFIG_FILE")"
cat > "$CONFIG_FILE" << EOF
# Ops Logger Configuration
TARGET_NAME="$TARGET_NAME"
LOG_DIR="$LOG_DIR"
PROMPT_NEW_SHELLS=$PROMPT_NEW_SHELLS
DEBUG=$DEBUG
EOF

# Create directories
mkdir -p "$LOG_DIR" "$LOG_DIR/verbose" "$LOG_DIR/recordings"

# Remove the in-progress marker
rm -f "__CONFIG_IN_PROGRESS__"

echo ""
echo "Configuration saved!"
echo "  Target name: $TARGET_NAME"
echo "  Log directory: $LOG_DIR"
echo "  Prompt new shells: $PROMPT_NEW_SHELLS"
echo "  Debug mode: $DEBUG"
echo ""
echo "Now run: prefix+L to start logging (or ops-logger --start)"
echo "Press ENTER to close this window..."
read
EOSCRIPT
        sed -i "s|__CONFIG_IN_PROGRESS__|$CONFIG_IN_PROGRESS|g" "$config_script"
        chmod +x "$config_script"

        # Open new window for config (export shared validators so the
        # separate config_script process can call the same functions)
        export -f validate_target_name validate_log_dir
        bash "$config_script"; rm -f "$config_script"
        return 0
    fi
    
    # For manual --config or non-tmux environments (GitHub version approach)
    echo "Red Team Terminal Logger - First Time Setup"
    echo "==========================================="
    echo ""

    CONFIG_FILE="${HOME}/.ops-logger.conf"
    DEFAULT_TARGET="target-$(hostname | tr '.' '-')"
    DEFAULT_LOG_DIR="${HOME}/OperationLogs"

    # Detect whether we're in a tty
    if [[ ! -t 0 ]]; then
        echo "Error: Cannot prompt user in non-interactive shell."
        return 1
    fi

    read -p "Enter target name [$DEFAULT_TARGET]: " TARGET_NAME
    TARGET_NAME="$(validate_target_name "$TARGET_NAME")"

    read -p "Enter log directory [$DEFAULT_LOG_DIR]: " LOG_DIR
    LOG_DIR="${LOG_DIR:-$DEFAULT_LOG_DIR}"
    while ! validate_log_dir "$LOG_DIR"; do
        echo "Log directory contains a disallowed character (quote, backtick, dollar sign, semicolon, pipe, or ampersand). Please try again."
        read -p "Enter log directory [$DEFAULT_LOG_DIR]: " LOG_DIR
        LOG_DIR="${LOG_DIR:-$DEFAULT_LOG_DIR}"
    done

    read -p "Prompt for logging in new shells? [Y/n]: " PROMPT_NEW_SHELLS
    [[ "${PROMPT_NEW_SHELLS,,}" == "n" ]] && PROMPT_NEW_SHELLS=false || PROMPT_NEW_SHELLS=true

    read -p "Enable debug logging? [y/N]: " DEBUG
    [[ "${DEBUG,,}" == "y" ]] && DEBUG=true || DEBUG=false

    # Save config
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" <<EOF
# Ops Logger Configuration
TARGET_NAME="$TARGET_NAME"
LOG_DIR="$LOG_DIR"
PROMPT_NEW_SHELLS=$PROMPT_NEW_SHELLS
DEBUG=$DEBUG
EOF

    mkdir -p "$LOG_DIR" "$LOG_DIR/verbose" "$LOG_DIR/recordings"

    echo ""
    echo "Configuration saved!"
    echo "  Target name: $TARGET_NAME"
    echo "  Log directory: $LOG_DIR"
    echo "  Prompt new shells: $PROMPT_NEW_SHELLS"
    echo "  Debug mode: $DEBUG"
    echo ""
    echo "Now run: prefix+L to start logging (or ops-logger --start)"
}

# Keep the ensure_config from local version
ensure_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        create_config "true" || return 1
        # If configuration is in progress, abort the current operation
        if [[ -f "$CONFIG_IN_PROGRESS" ]]; then
            return 1
        fi
    fi
    return 0
}

# ================================================================
# MAIN USER FUNCTIONS
# ================================================================

with_logging_lock() {
    local id=$1 fd rc
    command -v flock >/dev/null 2>&1 || { printf 'ERROR: flock is required\n' >&2; return 1; }
    shift
    exec {fd}> "$OPS_RUNTIME_DIR/ops-transition-$id.lock" || return 1
    if ! flock -n "$fd"; then
        printf 'Another logging transition is in progress for this pane\n' >&2
        exec {fd}>&-
        return 1
    fi
    "$@"
    rc=$?
    flock -u "$fd"
    exec {fd}>&-
    return "$rc"
}

start_logging() {
    with_logging_lock "$(get_pane_id)" start_logging_unlocked
}

start_logging_unlocked() {
    # Auto-setup config with prompts on first logging start
    ensure_config || return 1
    load_config || return 1
    
    local id=$(get_pane_id)
    is_logging_active "$id" && {
        echo "Already logging"
        return 0
    }
    
    local csv_log dep
    for dep in tmux tail flock; do
        if is_tmux && ! command -v "$dep" >/dev/null 2>&1; then
            printf 'ERROR: required command missing: %s\n' "$dep" >&2
            return 1
        fi
    done
    [[ -f "${LOG_MARKER}-${id}" ]] && remove_logging "$id"
    csv_log=$(setup_csv_log "$TARGET_NAME" "$LOG_DIR") || return 1
    
    install_logging "$id" "$csv_log" "$TARGET_NAME" "$LOG_DIR"
}

stop_logging() {
    with_logging_lock "$(get_pane_id)" stop_logging_unlocked
}

stop_logging_unlocked() {
    local id=$(get_pane_id)
    [[ -f "${LOG_MARKER}-${id}" ]] || {
        echo "Not logging"
        return 0
    }
    
    remove_logging "$id"
}

toggle_logging() {
    local id=$(get_pane_id)
    if [[ -f "${LOG_MARKER}-${id}" ]]; then stop_logging; else start_logging; fi
}

toggle_recording() {
    local id=$(get_pane_id)
    # Load existing config or use defaults
    [[ -f "$CONFIG_FILE" ]] && load_config || { TARGET_NAME="$DEFAULT_TARGET"; LOG_DIR="$DEFAULT_LOG_DIR"; }
    
    is_recording_active "$id" && stop_recording "$id" || start_recording "$id" "$TARGET_NAME" "$LOG_DIR"
}

prompt_for_logging() {
    local id
    id=$(get_pane_id)

    # Debug logging to see what's happening
    log_debug "prompt_for_logging called for pane: $id"
    log_debug "TMUX_PANE: ${TMUX_PANE:-'not set'}"

    # Avoid recursion with a pane-specific lock - BUT with timeout
    local lock_file="${OPS_RUNTIME_DIR}/ops-logger-prompted-${id}"
    if [[ -f "$lock_file" ]]; then
        # Check if lock file is stale (older than 30 seconds)
        if [[ $(find "$lock_file" -mmin +0.5 2>/dev/null) ]]; then
            log_debug "Removing stale lock file"
            rm -f "$lock_file"
        else
            log_debug "Recent lock file exists, returning"
            return 0
        fi
    fi
    touch "$lock_file"

    # Cleanup function to ensure lock file is always removed
    cleanup_lock() {
        rm -f "$lock_file"
        log_debug "Lock file cleaned up"
    }
    trap cleanup_lock EXIT

    is_logging_active "$id" && {
        log_debug "Already logging, returning"
        cleanup_lock
        return 0
    }

    load_config
    log_debug "Config loaded - PROMPT_NEW_SHELLS: $PROMPT_NEW_SHELLS"

    [[ "$PROMPT_NEW_SHELLS" != "true" ]] && {
        log_debug "Prompting disabled, returning"
        cleanup_lock
        return 0
    }

    # Use tmux display-popup for proper interaction in tmux
    if is_tmux; then
        log_debug "In tmux, creating popup"

        # Create a temporary script for the popup
        local popup_script
        popup_script=$(mktemp "${OPS_RUNTIME_DIR}/ops-prompt-${id}-XXXXXX.sh")
        if [[ -z "$popup_script" ]]; then
            log_debug "ERROR: failed to create popup script"
            cleanup_lock
            return 1
        fi
        local script_path=$(readlink -f "$0")
        
        cat > "$popup_script" << 'EOPOPUP'
#!/bin/bash
echo "Start logging this shell?"
echo ""
echo "  [Y]es - Start logging"
echo "  [N]o  - Skip logging"
echo ""
read -n 1 -p "Choice [Y/n]: " response
echo ""

if [[ -z "$response" || "${response,,}" == "y" ]]; then
    echo "Starting logging..."
    __SCRIPT_PATH__ --start
    echo "Logging started!"
    sleep 2
else
    echo "Logging skipped."
    sleep 1
fi
EOPOPUP
        
        # Replace placeholder with actual script path
        sed -i "s|__SCRIPT_PATH__|$script_path|g" "$popup_script"
        chmod +x "$popup_script"
        
        log_debug "Popup script created, calling display-popup"

        # Use tmux display-popup for proper interaction
        tmux display-popup -E -w 50 -h 10 -T "Ops Logger" "bash '$popup_script'; rm -f '$popup_script'"

        log_debug "display-popup completed"

    else
        log_debug "Not in tmux, using direct prompt"

        # Direct shell - standard approach
        echo "Start logging this shell?"
        echo ""
        echo "  [Y]es - Start logging"
        echo "  [N]o  - Skip logging"
        echo ""
        
        if read -t 10 -n 1 -p "Choice [Y/n]: " response; then
            echo ""
            if [[ -z "$response" || "${response,,}" == "y" ]]; then
                start_logging
                echo "Logging started!"
            else
                echo "Logging skipped."
            fi
        else
            echo ""
            echo "Timeout - logging skipped."
        fi
    fi
    
    # Clean up will be handled by trap
    log_debug "prompt_for_logging completed"
}

# ================================================================
# TMUX INTEGRATION
# ================================================================

install_tmux_keys() {
    load_config

    if is_tmux; then
        local script_path
        script_path=$(readlink -f "$0")

        # Warn (but still bind) if L/R are already bound to something that
        # isn't this tool's own binding, so a pre-existing config (e.g.
        # oh-my-tmux's L -> resize-pane) isn't clobbered without notice.
        local key_check existing_binding
        for key_check in L R; do
            existing_binding=$(tmux list-keys "$key_check" 2>/dev/null | grep -E "[[:space:]]-T[[:space:]]+prefix([[:space:]]|$)")
            if [[ -n "$existing_binding" && "$existing_binding" != *"$script_path"* ]]; then
                echo "Warning: prefix+$key_check is already bound to something else, overwriting:" >&2
                echo "  $existing_binding" >&2
            fi
        done

        # Bind keys
        tmux bind-key L run-shell "bash -c '[ -f ~/.ops-logger.conf ] && tmux run-shell \"$script_path --toggle\" || tmux display-popup -E -w 80% -h 60% -T \"Ops Logger Config\" \"bash $script_path --toggle\"'"
        tmux bind-key R run-shell "'$script_path' --toggle-recording"

        # Create a wrapper script that exports the pane context
        if [[ "$PROMPT_NEW_SHELLS" == "true" ]]; then
            local hook_wrapper="${OPS_RUNTIME_DIR}/ops-logger-pane-wrapper.sh"
            cat > "$hook_wrapper" << EOWRAPPER
#!/bin/bash
# Wrapper that sets pane context and calls the prompt

# Sleep to let pane initialize
sleep 1

# Check config
if [ -f ~/.ops-logger.conf ]; then
    source ~/.ops-logger.conf
    if [ "\$PROMPT_NEW_SHELLS" = "true" ]; then
        # Get pane info in tmux context
        PANE_ID=\$(tmux display-message -p "#{session_name}-#{window_index}-#{pane_index}")
        
        # Check if already logging
        if [ ! -f "${LOG_MARKER}-\$PANE_ID" ]; then
            # Export the tmux pane reference for the script to use
            export TMUX_PANE=\$(tmux display-message -p "#{pane_id}")
            
            # Call the script with the pane context
            $script_path --prompt
        fi
    fi
fi
EOWRAPPER
            chmod +x "$hook_wrapper"
            
            tmux set-hook -g after-new-window "run-shell '$hook_wrapper'"
            tmux set-hook -g after-split-window "run-shell '$hook_wrapper'"
            echo "Hooks installed for new windows/panes"
        fi

        echo "Keys installed: $(get_tmux_prefix)+L (logging), $(get_tmux_prefix)+R (recording)"
        log_debug "Tmux key bindings installed"
    else
        echo "Not in tmux, no keys installed"
    fi
}

uninstall_tmux_keys() {
    if is_tmux; then
        tmux unbind-key L 2>/dev/null
        tmux unbind-key R 2>/dev/null
        tmux set-hook -gu after-new-window 2>/dev/null
        tmux set-hook -gu after-split-window 2>/dev/null
        echo "Tmux keys removed"
        log_debug "Tmux key bindings removed"
        
        # Remove our hook scripts
        rm -f "${OPS_RUNTIME_DIR}/ops-logger-hook-wrapper.sh" 2>/dev/null
        rm -f "${OPS_RUNTIME_DIR}/ops-logger-tmux-hook.sh" 2>/dev/null
        rm -f "${OPS_RUNTIME_DIR}/ops-logger-pane-wrapper.sh" 2>/dev/null
    fi
    
    # Also remove config file as user expected
    load_config
    local log_dir_for_cleanup="$LOG_DIR"
    
    # Remove config
    [[ -f "$CONFIG_FILE" ]] && rm -f "$CONFIG_FILE"
    
    # Remove debug log
    [[ -f "${log_dir_for_cleanup}/ops-logger-debug.log" ]] && rm -f "${log_dir_for_cleanup}/ops-logger-debug.log"
    
    echo "Configuration removed"
}

uninstall_all() {
    local id=$(get_pane_id)
    
    log_debug "Starting complete uninstall"
    
    # Stop active sessions
    is_logging_active "$id" && stop_logging
    is_recording_active "$id" && stop_recording "$id"
    
    # Remove tmux integration and config
    is_tmux && uninstall_tmux_keys
    
    # Clean up temp files
    rm -rf "$OPS_RUNTIME_DIR" 2>/dev/null
    
    echo "OpsLogger uninstalled completely"
}

show_status() {
    load_config
    local id=$(get_pane_id)
    
    echo "Red Team Terminal Logger Status:"
    echo "==============================="
    echo "Target: $TARGET_NAME"
    echo "Log directory: $LOG_DIR"
    echo "Debug mode: $DEBUG"
    if is_logging_active "$id"; then
        echo 'Logging: ACTIVE'
    elif [[ -f "${LOG_MARKER}-${id}" ]]; then
        echo 'Logging: FAILED or incomplete stop (inspect writer states below)'
    else
        echo 'Logging: INACTIVE'
    fi
    local run
    if run=$(logging_run_dir "$id"); then
        [[ ! -f $run/transcript ]] || printf 'Transcript: %s\n' "$(cat "$run/transcript")"
        [[ ! -f $run/capture ]] || printf 'Capture writer: %s\n' "$(cat "$run/capture")"
        [[ ! -f $run/summary ]] || printf 'Summary reader: %s\n' "$(cat "$run/summary")"
        [[ ! -f $run/csv ]] || printf 'CSV writer: %s\n' "$(cat "$run/csv")"
        if [[ -f $run/hook-ready ]]; then echo 'Shell hooks: installed'; else echo 'Shell hooks: unavailable (transcript only)'; fi
    fi
    echo "Recording: $(is_recording_active "$id" && echo "ACTIVE" || echo "INACTIVE")"
    echo "Public IP: $(get_public_ip)"
    echo "Asciinema: $(command -v asciinema >/dev/null 2>&1 && echo "INSTALLED" || echo "NOT INSTALLED")"
    
    if is_tmux; then
        echo "Environment: tmux ($(tmux display -p '#{session_name}'))"
        echo "Tmux prefix: $(get_tmux_prefix)"
        echo "ohmytmux: $(tmux show-options -g | grep -q "TMUX_CONF" && echo "DETECTED" || echo "NOT DETECTED")"
        echo "Normalized Pane ID: $id"
        
        # Check plugin installation status
        if check_tpm_installed; then
            echo "TPM: INSTALLED"
        else
            echo "TPM: NOT INSTALLED"
            print_tpm_install_instructions
        fi
        if check_tmux_logging_installed; then
            echo "tmux-logging plugin: INSTALLED"
        else
            echo "tmux-logging plugin: NOT INSTALLED"
            print_tmux_logging_install_instructions
        fi

        # Check if there's active pipe-pane logging
        echo "Active logging pipe: $( [[ $(tmux display-message -p -t "$(get_tmux_pane_ref)" '#{pane_pipe}') == 1 ]] && echo "YES" || echo "NO")"
    else
        echo "Environment: direct shell"
    fi
    
    # Show current log files
    local csv_log="${LOG_DIR}/${TARGET_NAME}_commands.csv"
    
    [[ -f "$csv_log" ]] && {
        echo "Current CSV log: $csv_log"
        echo "Commands logged: $(csv_record_count "$csv_log")"
    }
    
    # Show verbose logs with headers
    local verbose_dir="${LOG_DIR}/verbose"
    if [[ -d "$verbose_dir" ]]; then
        local verbose_files=$(find "$verbose_dir" -name "*${TARGET_NAME}*.log" -type f 2>/dev/null | wc -l)
        echo "Verbose log files: $verbose_files in $verbose_dir"
        if [[ "$verbose_files" -gt 0 ]]; then
            local latest_verbose=$(find "$verbose_dir" -name "*${TARGET_NAME}*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
            [[ -n "$latest_verbose" ]] && echo "Latest verbose log: $latest_verbose ($(du -h "$latest_verbose" | cut -f1))"
        fi
    fi
}

show_help() {
    echo "Red Team Terminal Logger - Professional Solution v2.7.0"
    echo "========================================================"
    echo "USAGE: $0 [OPTIONS]"
    echo ""
    echo "LOGGING CONTROLS:"
    echo "  --start               Start command/verbose logging"
    echo "  --stop                Stop logging"
    echo "  --toggle              Toggle logging on/off"
    echo ""
    echo "RECORDING CONTROLS:"
    echo "  --start-recording     Start terminal recording (requires asciinema)"
    echo "  --stop-recording      Stop recording"
    echo "  --toggle-recording    Toggle recording on/off"
    echo ""
    echo "SETUP & CONFIGURATION:"
    echo "  --prompt              Show logging prompt (for new shells)"
    echo "  --install             Install tmux keybindings"
    echo "  --uninstall           Remove keybindings/hooks and delete config"
    echo "  --uninstall-all       Also stop active logging/recording; wipe runtime state"
    echo "  --config              Configure settings"
    echo "  --save-config         Save config (internal use)"
    echo ""
    echo "INFO:"
    echo "  --status              Show current status"
    echo "  --help                Show this help"
    echo ""
    echo "DEBUG:"
    echo "  --debug-on            Enable debug logging"
    echo "  --debug-off           Disable debug logging"
    echo "  --debug-pipe          Raw pipe-pane capture (dev/debug)"
    echo ""
    echo "TMUX INTEGRATION:"
    echo "  Keys: prefix+L (toggle logging), prefix+R (recording)"
    echo "  Compatible with ohmytmux themes and window naming"
    echo "  Auto-prompts for new windows/panes (configurable)"
    echo ""
    echo "v2.7.0 CHANGELOG:"
    echo "  - Complete per-pane transcripts independent of the capped summary"
    echo "  - Ordered command boundaries, repeated CSV entries, and safe hook cleanup"
    echo "  - Acknowledged writer state and explicit pane labels"
    echo "  - Runtime/log directories hardened to mode 700 with ownership verification"
    echo "  - TARGET_NAME/LOG_DIR input validation to close shell-injection sinks"
    echo "  - Temp files created via mktemp instead of predictable paths"
    echo "  - Removed 165 lines of dead/duplicate hook-generation code"
    echo "  - Fixed --save-config dispatching to a nonexistent function"
}

# Redirect stdout/stderr to the real tty when invoked from a tmux
# keybinding/run-shell context, whose fds otherwise point at tmux's
# control pipe rather than a terminal a user can see.
ensure_direct_tty() {
    if is_tmux && [[ -t 1 ]]; then
        local tty=$(tty 2>/dev/null || echo "/dev/tty")
        exec 1>$tty 2>$tty
    fi
}

# Main command handler with output handling
main() {
    # Always ensure direct terminal output for tmux operations
    ensure_direct_tty

    case "$1" in
        --start)             start_logging ;;
        --stop)              stop_logging ;;
        --toggle)            toggle_logging ;;
        --start-recording)   [[ -f "$CONFIG_FILE" ]] && load_config || { TARGET_NAME="$DEFAULT_TARGET"; LOG_DIR="$DEFAULT_LOG_DIR"; }; start_recording "$(get_pane_id)" "$TARGET_NAME" "$LOG_DIR" ;;
        --stop-recording)    stop_recording "$(get_pane_id)" ;;
        --toggle-recording)  toggle_recording ;;
        --prompt)            prompt_for_logging ;;
        --install)           install_tmux_keys ;;
        --uninstall)         uninstall_tmux_keys ;;
        --uninstall-all)     uninstall_all ;;
        --config)            create_config ;;
        --save-config)       save_config ;;
        --status)            show_status ;;
        --debug-pipe)        
            load_config || { TARGET_NAME="$DEFAULT_TARGET"; LOG_DIR="$DEFAULT_LOG_DIR"; }
            local id=$(get_pane_id)
            local tmux_pane_ref=$(get_tmux_pane_ref)
            start_debug_verbose_logging "$id" "$tmux_pane_ref" "$TARGET_NAME" "$LOG_DIR"
            ;;
        --debug-on)          [[ -f "$CONFIG_FILE" ]] && { load_config; DEBUG=true; save_config; } || echo "Run --config first to set up configuration"; echo "Debug logging enabled" ;;
        --debug-off)         [[ -f "$CONFIG_FILE" ]] && { load_config; DEBUG=false; save_config; } || echo "Run --config first to set up configuration"; echo "Debug logging disabled" ;;
        --help|'')           show_help ;;
        *)                   echo "Unknown option: $1. Use --help" ;;
    esac
}

# ShellOpsLog compatibility layer
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    export REDTEAM_LOGGER_PATH="${BASH_SOURCE[0]}"
    
    start_operation_log() {
        local auto_start=0
        local log_dir="$HOME/OperationLogs"
        
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -AutoStart|-autostart) auto_start=1; shift ;;
                *) log_dir="$1"; shift ;;
            esac
        done
        
        [[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"
        
        LOG_DIR="$log_dir"
        TARGET_NAME="${TARGET_NAME:-$DEFAULT_TARGET}"
        save_config
        
        if [[ "$auto_start" -eq 1 ]]; then
            start_logging
        else
            "$REDTEAM_LOGGER_PATH" --prompt
        fi
    }
    
    stop_operation_log() {
        stop_logging
    }
    
    log_debug "ShellOpsLog compatibility layer loaded"
else
    # Script is being executed directly
    main "$@"
fi
