#!/bin/ksh

###############################################################################
# Collect HSM configuration from F5 BIG-IP devices
#
# Usage:
#   ./get_nethsm_info.sh
#   ./get_nethsm_info.sh my_hosts.inv
#   ./get_nethsm_info.sh my_hosts.inv output.tsv
#
# Environment:
#   USER     Base SSH username. "_net" is appended automatically.
#   PASSNET  SSH password for the elevated account.
###############################################################################

HOSTS_FILE="${1:-hosts.inv}"
OUTPUT_FILE="${2:-nethsm_inventory.tsv}"

SSH_USER="${USER}_net"

VTL_COMMAND='bash -c "/usr/safenet/lunaclient/bin/vtl listServers"'
PARTITION_COMMAND='show sys crypto encrypted-attributes'

SSH_OPTIONS="
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o ConnectTimeout=15
    -o ServerAliveInterval=10
    -o ServerAliveCountMax=2
"

START_TIME=$(date +%s)

###############################################################################
# Validate prerequisites
###############################################################################

if [ -z "$USER" ]; then
    echo "ERROR: USER is not set."
    exit 1
fi

if [ -z "$PASSNET" ]; then
    echo "ERROR: PASSNET is not set."
    exit 1
fi

if [ ! -r "$HOSTS_FILE" ]; then
    echo "ERROR: Cannot read hosts file: $HOSTS_FILE"
    exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
    echo "ERROR: sshpass is not installed or is not in PATH."
    exit 1
fi

###############################################################################
# Temporary files
###############################################################################

TMP_BASE="${TMPDIR:-/tmp}/nethsm_inventory.$$"
CLEAN_HOSTS="${TMP_BASE}.hosts"
VTL_OUTPUT="${TMP_BASE}.vtl"
PARTITION_OUTPUT="${TMP_BASE}.partition"
SSH_ERROR="${TMP_BASE}.error"

cleanup()
{
    rm -f "$CLEAN_HOSTS" \
          "$VTL_OUTPUT" \
          "$PARTITION_OUTPUT" \
          "$SSH_ERROR"
}

trap cleanup EXIT HUP INT TERM

# Remove blank lines, comments and surrounding whitespace.
awk '
{
    sub(/\r$/, "")
    sub(/^[[:space:]]+/, "")
    sub(/[[:space:]]+$/, "")
}
$0 != "" && $0 !~ /^#/ {
    print
}
' "$HOSTS_FILE" > "$CLEAN_HOSTS"

TOTAL_HOSTS=$(awk 'END { print NR + 0 }' "$CLEAN_HOSTS")

if [ "$TOTAL_HOSTS" -eq 0 ]; then
    echo "ERROR: No hosts found in $HOSTS_FILE."
    exit 1
fi

###############################################################################
# Initialise output
###############################################################################

printf 'hostname\tserver_ips\tnethsm_partition\n' > "$OUTPUT_FILE"

echo "Input file : $HOSTS_FILE"
echo "Output file: $OUTPUT_FILE"
echo "SSH user   : $SSH_USER"
echo "Hosts      : $TOTAL_HOSTS"
echo

CURRENT_HOST=0
SUCCESSFUL_HOSTS=0
FAILED_HOSTS=0

###############################################################################
# Process hosts
###############################################################################

while IFS= read -r HOST
do
    CURRENT_HOST=$((CURRENT_HOST + 1))

    echo "======================================================================"
    echo "[$CURRENT_HOST/$TOTAL_HOSTS] Processing: $HOST"
    echo "======================================================================"

    SERVER_IPS=""
    PARTITION_NAME=""
    VTL_STATUS=0
    PARTITION_STATUS=0

    ###########################################################################
    # Obtain the configured Luna HSM server IP addresses
    ###########################################################################

    echo "+ ssh ${SSH_USER}@${HOST} '${VTL_COMMAND}'"

    sshpass -p "$PASSNET" \
        ssh $SSH_OPTIONS \
        "${SSH_USER}@${HOST}" \
        "$VTL_COMMAND" \
        > "$VTL_OUTPUT" 2> "$SSH_ERROR"

    VTL_STATUS=$?

    if [ "$VTL_STATUS" -eq 0 ]; then
        SERVER_IPS=$(
            awk '
            /^[[:space:]]*Server[[:space:]]*:/ {
                line = $0
                sub(/^[[:space:]]*Server[[:space:]]*:[[:space:]]*/, "", line)
                sub(/[[:space:]]+$/, "", line)

                if (line != "") {
                    if (result != "")
                        result = result "," line
                    else
                        result = line
                }
            }
            END {
                print result
            }
            ' "$VTL_OUTPUT"
        )

        if [ -n "$SERVER_IPS" ]; then
            echo "  Server IPs       : $SERVER_IPS"
        else
            echo "  WARNING: No HSM server IPs found."
        fi
    else
        echo "  ERROR: Failed to retrieve HSM server IPs (SSH exit $VTL_STATUS)."

        if [ -s "$SSH_ERROR" ]; then
            sed 's/^/  /' "$SSH_ERROR"
        fi
    fi

    ###########################################################################
    # Obtain the encrypted nethsm_partition object name
    ###########################################################################

    echo "+ ssh ${SSH_USER}@${HOST} '${PARTITION_COMMAND}'"

    sshpass -p "$PASSNET" \
        ssh $SSH_OPTIONS \
        "${SSH_USER}@${HOST}" \
        "$PARTITION_COMMAND" \
        > "$PARTITION_OUTPUT" 2> "$SSH_ERROR"

    PARTITION_STATUS=$?

    if [ "$PARTITION_STATUS" -eq 0 ]; then
        PARTITION_NAME=$(
            awk '
            $1 == "nethsm_partition" {
                print $2
                exit
            }
            ' "$PARTITION_OUTPUT"
        )

        if [ -n "$PARTITION_NAME" ]; then
            echo "  HSM partition    : $PARTITION_NAME"
        else
            echo "  WARNING: nethsm_partition was not found."
        fi
    else
        echo "  ERROR: Failed to retrieve nethsm_partition (SSH exit $PARTITION_STATUS)."

        if [ -s "$SSH_ERROR" ]; then
            sed 's/^/  /' "$SSH_ERROR"
        fi
    fi

    ###########################################################################
    # Write one row for every host, including hosts with missing information
    ###########################################################################

    printf '%s\t%s\t%s\n' \
        "$HOST" \
        "$SERVER_IPS" \
        "$PARTITION_NAME" >> "$OUTPUT_FILE"

    if [ "$VTL_STATUS" -eq 0 ] && [ "$PARTITION_STATUS" -eq 0 ]; then
        SUCCESSFUL_HOSTS=$((SUCCESSFUL_HOSTS + 1))
        echo "  Result            : SUCCESS"
    else
        FAILED_HOSTS=$((FAILED_HOSTS + 1))
        echo "  Result            : FAILED/PARTIAL"
    fi

    echo

done < "$CLEAN_HOSTS"

###############################################################################
# Summary and elapsed time
###############################################################################

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

ELAPSED_HOURS=$((ELAPSED / 3600))
ELAPSED_MINUTES=$(((ELAPSED % 3600) / 60))
ELAPSED_SECONDS=$((ELAPSED % 60))

FORMATTED_TIME=$(printf '%02d:%02d:%02d' \
    "$ELAPSED_HOURS" \
    "$ELAPSED_MINUTES" \
    "$ELAPSED_SECONDS")

echo "======================================================================"
echo "Completed"
echo "======================================================================"
echo "Processed          : $TOTAL_HOSTS"
echo "Successful         : $SUCCESSFUL_HOSTS"
echo "Failed/partial     : $FAILED_HOSTS"
echo "Output file        : $OUTPUT_FILE"
echo "Elapsed time       : $FORMATTED_TIME"
