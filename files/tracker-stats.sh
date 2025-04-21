#!/bin/bash
# CLI tool to view email tracking stats

DATA_FILE="/root/Tools/tracker/data/tracking_data.json"

function show_summary() {
    if [ ! -f "$DATA_FILE" ]; then
        echo "No tracking data found."
        exit 1
    fi
    
    echo "Email Tracking Summary:"
    echo "======================="
    jq -r 'to_entries | sort_by(.value | length) | reverse | .[] | "\(.key): \(.value | length) views"' $DATA_FILE
}

function show_details() {
    ID=$1
    if [ ! -f "$DATA_FILE" ]; then
        echo "No tracking data found."
        exit 1
    fi
    
    echo "Details for tracking ID: $ID"
    echo "=========================="
    jq -r --arg id "$ID" '.[$id] | if . then .[] | "\(.timestamp) | \(.ip_address) | \(.user_agent)" else "No data found for this ID" end' $DATA_FILE
}

case "$1" in
    "list")
        show_summary
        ;;
    "details")
        if [ -z "$2" ]; then
            echo "Usage: $0 details TRACKING_ID"
            exit 1
        fi
        show_details "$2"
        ;;
    *)
        echo "Usage: $0 [list|details TRACKING_ID]"
        echo "  list         - Show summary of all tracking IDs"
        echo "  details ID   - Show details for specific tracking ID"
        ;;
esac