#!/bin/bash

# Default values
RECOMMENDED_VERSION=""
SHOW_VULNERABLE_ONLY=false

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
        -r|--recommended-version)
            RECOMMENDED_VERSION="$2"
            shift
            shift
            ;;
        --show-vulnerable-only)
            SHOW_VULNERABLE_ONLY=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 --ips <IPs> --username <Username> --command <Command> [options]"
            echo ""
            echo "Options:"
            echo "  -i, --ips <IPs>                 Comma-separated list of IP addresses"
            echo "  -u, --username <Username>       SSH username"
            echo "  -c, --command <Command>         Command to execute on remote hosts"
            echo "  -k, --keypath <KeyPath>         Path to SSH private key (optional)"
            echo "  -r, --recommended-version <Ver> Minimum safe version (e.g.: cloud-init-23.4-19.el9_5.6.noarch)"
            echo "  --show-vulnerable-only          Only show vulnerable servers in output"
            echo "  -h, --help                      Show this help message"
            exit 0
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

# Arrays to track results
VULNERABLE_IPS=()
ALL_RESULTS=()

# Function to extract numeric version from package string
get_numeric_version() {
    local package_string="$1"
    # Extract version pattern: numbers and dots between hyphens
    if [[ $package_string =~ -[0-9]+(\.[0-9]+)*[^-]* ]]; then
        local version_part="${BASH_REMATCH[0]:1}"  # Remove the leading hyphen
        # Further clean up to get just the numeric version
        if [[ $version_part =~ ^[0-9]+(\.[0-9]+)* ]]; then
            echo "${BASH_REMATCH[0]}"
            return 0
        fi
    fi
    return 1
}

# Function to compare versions
compare_versions() {
    local installed_ver="$1"
    local recommended_ver="$2"
    
    # Extract numeric versions
    local installed_numeric=$(get_numeric_version "$installed_ver")
    local recommended_numeric=$(get_numeric_version "$recommended_ver")
    
    if [[ -z "$installed_numeric" || -z "$recommended_numeric" ]]; then
        return 1  # If we can't parse, assume vulnerable
    fi
    
    # Use sort -V for version comparison
    local sorted_versions=$(printf "%s\n%s" "$installed_numeric" "$recommended_numeric" | sort -V)
    local first_version=$(echo "$sorted_versions" | head -n1)
    
    # If installed version is first (lower) in sorted list, it's vulnerable
    if [[ "$first_version" == "$installed_numeric" && "$installed_numeric" != "$recommended_numeric" ]]; then
        return 0  # Vulnerable
    else
        return 1  # Not vulnerable
    fi
}

# Show vulnerability info if recommended version is provided
if [[ -n "$RECOMMENDED_VERSION" ]]; then
    echo "================================================================"
    echo "NESSUS VULNERABILITY VERIFICATION"
    echo "================================================================"
    echo "Recommended Version: $RECOMMENDED_VERSION"
    echo "Checking for vulnerable packages..."
    echo "================================================================"
    echo ""
fi

for ip in "${TARGETS[@]}"; do
    if [[ "$SHOW_VULNERABLE_ONLY" != true ]]; then
        echo -e "\nConnecting to $ip as $USERNAME..."
        echo "Authorized uses only. All activity may be monitored and reported."
    fi

    # Prepare SSH command
    SSH_CMD="ssh"
    if [[ -n "$KEYPATH" ]]; then
        if [[ ! -f "$KEYPATH" ]]; then
            echo "Error: Key file not found at: $KEYPATH" >&2
            continue
        fi
        SSH_CMD+=" -i \"$KEYPATH\""
    fi

    SSH_CMD+=" -o StrictHostKeyChecking=no -o ConnectTimeout=10"
    SSH_CMD+=" \"$USERNAME@$ip\" \"$COMMAND\""

    # Execute command
    if [[ "$SHOW_VULNERABLE_ONLY" != true ]]; then
        echo "Last login: $(date +'%a %b %d %H:%M:%S %Y')"
        echo "[$USERNAME@$ip]$ $COMMAND"
    fi
    
    OUTPUT=$(eval "$SSH_CMD" 2>/dev/null)
    EXIT_STATUS=$?
    
    if [[ "$SHOW_VULNERABLE_ONLY" != true ]]; then
        echo "$OUTPUT"
    fi

    if [[ $EXIT_STATUS -ne 0 ]]; then
        if [[ "$SHOW_VULNERABLE_ONLY" != true ]]; then
            echo "Command failed (Exit Code: $EXIT_STATUS)" >&2
        fi
    else
        # Check for vulnerability if recommended version is provided
        if [[ -n "$RECOMMENDED_VERSION" && -n "$OUTPUT" ]]; then
            if [[ "$OUTPUT" =~ "not installed" || "$OUTPUT" =~ "not found" || "$OUTPUT" =~ "No packages found" ]]; then
                # Package not installed - not vulnerable
                RESULT="NOT_INSTALLED"
            else
                # Compare versions
                if compare_versions "$OUTPUT" "$RECOMMENDED_VERSION"; then
                    VULNERABLE_IPS+=("$ip:$OUTPUT")
                    RESULT="VULNERABLE"
                else
                    RESULT="SAFE"
                fi
            fi
            # Store result
            ALL_RESULTS+=("$ip:$OUTPUT:$RESULT")
        fi
    fi
done

# Show vulnerability summary if recommended version was provided
if [[ -n "$RECOMMENDED_VERSION" ]]; then
    echo ""
    echo "================================================================"
    
    if [[ ${#VULNERABLE_IPS[@]} -gt 0 ]]; then
        echo "VULNERABLE SERVERS FOUND: ${#VULNERABLE_IPS[@]}/${#TARGETS[@]}"
        echo "================================================================"
        echo "The following servers have vulnerable versions:"
        for vuln_server in "${VULNERABLE_IPS[@]}"; do
            ip="${vuln_server%:*}"
            version="${vuln_server#*:}"
            echo "  $ip - $version" >&2  # Output to stderr for emphasis
        done
        echo "================================================================"
        # Exit with error code if vulnerable servers found
        exit 1
    else
        echo "SCAN COMPLETED - NO VULNERABLE SERVERS FOUND"
        echo "================================================================"
    fi
fi

if [[ "$SHOW_VULNERABLE_ONLY" != true ]]; then
    echo -e "\nOperation completed. Checked ${#TARGETS[@]} hosts."
fi

# If showing vulnerable only and there are vulnerable IPs, print them
if [[ "$SHOW_VULNERABLE_ONLY" == true && ${#VULNERABLE_IPS[@]} -gt 0 ]]; then
    echo "VULNERABLE SERVERS:"
    for vuln_server in "${VULNERABLE_IPS[@]}"; do
        echo "$vuln_server"
    done
fi
