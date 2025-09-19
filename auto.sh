#!/bin/bash

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--ips)
            IPS="$2"
            shift
            shift
            ;;
        -u|--username)
            USERNAME="$2"
            shift
            shift
            ;;
        -c|--command)
            COMMAND="$2"
            shift
            shift
            ;;
        -k|--keypath)
            KEYPATH="$2"
            shift
            shift
            ;;
        *)
            echo "Unknown parameter: $1"
            exit 1
            ;;
    esac
done

# Check for required parameters
if [[ -z "$IPS" || -z "$USERNAME" || -z "$COMMAND" ]]; then
    echo "Usage: $0 --ips <IPs> --username <Username> --command <Command> [--keypath <KeyPath>]"
    exit 1
fi

# Split IPs into array
IFS=', ' read -ra TARGETS <<< "$IPS"

for ip in "${TARGETS[@]}"; do
    echo -e "\nConnecting to $ip as $USERNAME..."
    echo "Authorized uses only. All activity may be monitored and reported."

    # Prepare SSH command
    SSH_CMD="ssh"
    if [[ -n "$KEYPATH" ]]; then
        if [[ ! -f "$KEYPATH" ]]; then
            echo "Error: Key file not found at: $KEYPATH"
            continue
        fi
        SSH_CMD+=" -i \"$KEYPATH\""
    fi

    SSH_CMD+=" -o StrictHostKeyChecking=no -o ConnectTimeout=10"
    SSH_CMD+=" \"$USERNAME@$ip\" \"$COMMAND\""

    # Execute command
    echo "Last login: $(date +'%a %b %d %H:%M:%S %Y')"
    echo "[$USERNAME@$ip]$ $COMMAND"
    eval "$SSH_CMD"
    EXIT_STATUS=$?

    if [[ $EXIT_STATUS -ne 0 ]]; then
        echo "Command failed (Exit Code: $EXIT_STATUS)" >&2
    fi
done

echo -e "\nOperation completed. Checked ${#TARGETS[@]} hosts."
