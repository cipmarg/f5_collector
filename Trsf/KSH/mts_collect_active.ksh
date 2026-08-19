#!/bin/ksh

# MTS data collector for BIG-IP
#
# Usage:
#   ./mts_collect_active.ksh <device>
#   ./mts_collect_active.ksh <device_list_file>
#
# Examples:
#   ./mts_collect_active.ksh gbs1o-d1-ecvwa-0437a
#   ./mts_collect_active.ksh devices.lst
#
# Device-list format:
#   - one device per line
#   - blank lines are ignored
#   - lines beginning with # are ignored
#
# Authentication:
#   - SSH username is taken from $USER
#   - if $SSHPASS is already set, it is used
#   - otherwise the script prompts once for the password and stores it in
#     SSHPASS for the duration of this script
#
# Collection:
#   - determines the active member for every supplied device
#   - reuses one persistent SSH connection for all MTS collection commands
#     for that host
#   - does not change BIG-IP CLI pager/display-threshold preferences
#   - feeds "y" in case BIG-IP asks to display all items
#   - performs grep locally because the remote account lands directly in tmsh
#   - preserves the original MTS section markers and displayed command lines
#     because the MTS VBA parser depends on them

if [ $# -ne 1 ]; then
    echo "Usage: $0 <device|device_list_file>"
    exit 1
fi

INPUT="$1"
SSH_USER="$USER"

if [ -z "$SSH_USER" ]; then
    echo "ERROR: \$USER is not set."
    exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
    echo "ERROR: ssh is not available."
    exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
    echo "ERROR: sshpass is not available."
    exit 1
fi

DEVICE_LIST_TMP="/tmp/mts_devices.$$"

CONTROL_SOCKET=""
PROBE_ERR=""
CMD_RAW=""
CMD_TMP=""
CMD_ERR=""
OUT_TMP=""
OUT_FILE=""
MASTER_HOST=""
MASTER_OPEN=0
PASSWORD_ECHO_OFF=0
HOST_INDEX=0

# Keep these options conservative for older jump-server OpenSSH versions.
SSH_OPTS="-o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

cleanup_host()
{
    if [ "$MASTER_OPEN" -eq 1 ] && [ -n "$MASTER_HOST" ] && [ -n "$CONTROL_SOCKET" ]; then
        ssh $SSH_OPTS -S "$CONTROL_SOCKET" -O exit "$SSH_USER@$MASTER_HOST" >/dev/null 2>&1
    fi

    [ -n "$CONTROL_SOCKET" ] && rm -f "$CONTROL_SOCKET"
    [ -n "$PROBE_ERR" ] && rm -f "$PROBE_ERR"
    [ -n "$CMD_RAW" ] && rm -f "$CMD_RAW"
    [ -n "$CMD_TMP" ] && rm -f "$CMD_TMP"
    [ -n "$CMD_ERR" ] && rm -f "$CMD_ERR"

    if [ -n "$OUT_TMP" ] && [ -f "$OUT_TMP" ]; then
        rm -f "$OUT_TMP"
    fi

    CONTROL_SOCKET=""
    PROBE_ERR=""
    CMD_RAW=""
    CMD_TMP=""
    CMD_ERR=""
    OUT_TMP=""
    OUT_FILE=""
    MASTER_HOST=""
    MASTER_OPEN=0
}

cleanup_all()
{
    if [ "$PASSWORD_ECHO_OFF" -eq 1 ]; then
        stty echo >/dev/null 2>&1
        PASSWORD_ECHO_OFF=0
        printf "\n"
    fi

    cleanup_host
    rm -f "$DEVICE_LIST_TMP"

    # This only clears the variable inside this script process.
    SSHPASS=""
    export SSHPASS
}

abort_script()
{
    echo
    echo "Aborted."
    cleanup_all
    exit 130
}

trap 'abort_script' INT TERM HUP
trap 'cleanup_all; exit 131' QUIT

# ------------------------------------------------------------
# Build the device list
# ------------------------------------------------------------

if [ -f "$INPUT" ]; then
    # Remove Windows CR characters, trim whitespace and ignore blanks/comments.
    tr -d '\015' < "$INPUT" | \
        sed -e 's/^[[:space:]]*//' \
            -e 's/[[:space:]]*$//' \
            -e '/^$/d' \
            -e '/^#/d' > "$DEVICE_LIST_TMP"

    echo "Using device list: $INPUT"
else
    printf "%s\n" "$INPUT" > "$DEVICE_LIST_TMP"
fi

TOTAL_HOSTS=`wc -l < "$DEVICE_LIST_TMP" | tr -d ' '`

if [ -z "$TOTAL_HOSTS" ] || [ "$TOTAL_HOSTS" -eq 0 ]; then
    echo "ERROR: No devices found."
    cleanup_all
    exit 1
fi

# ------------------------------------------------------------
# Password
# ------------------------------------------------------------

if [ -n "$SSHPASS" ]; then
    echo "Using password from \$SSHPASS."
else
    printf "Enter password for %s: " "$SSH_USER"
    stty -echo
    PASSWORD_ECHO_OFF=1
    read SSHPASS
    READ_RC=$?
    stty echo
    PASSWORD_ECHO_OFF=0
    printf "\n"

    if [ "$READ_RC" -ne 0 ] || [ -z "$SSHPASS" ]; then
        echo "ERROR: No password entered."
        cleanup_all
        exit 1
    fi
fi

export SSHPASS

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

short_name()
{
    echo "$1" | sed 's/\..*$//'
}

lower_name()
{
    short_name "$1" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz'
}

peer_name()
{
    _peer_input="$1"
    _peer_label=`echo "$_peer_input" | sed 's/\..*$//'`
    _peer_suffix=`echo "$_peer_input" | sed "s/^${_peer_label}//"`

    case "$_peer_label" in
        *a) echo "`echo "$_peer_label" | sed 's/a$//'`b${_peer_suffix}" ;;
        *A) echo "`echo "$_peer_label" | sed 's/A$//'`B${_peer_suffix}" ;;
        *b) echo "`echo "$_peer_label" | sed 's/b$//'`a${_peer_suffix}" ;;
        *B) echo "`echo "$_peer_label" | sed 's/B$//'`A${_peer_suffix}" ;;
        *)  echo "" ;;
    esac
}

probe_device()
{
    _probe_host="$1"
    rm -f "$PROBE_ERR"

    PROBE_OUTPUT=`printf 'y\n' | sshpass -e ssh $SSH_OPTS "$SSH_USER@$_probe_host" "show cm device" 2>"$PROBE_ERR"`
    PROBE_RC=$?

    if [ "$PROBE_RC" -ne 0 ]; then
        return 1
    fi

    return 0
}

state_for_host()
{
    _state_host=`lower_name "$1"`
    echo "$2" | awk -v t="$_state_host" '/^CentMgmt::Device:/ {d=$2; sub(/\..*$/, "", d); inblk=(tolower(d)==tolower(t)); next} inblk && /Device HA State/ {print tolower($NF); exit}'
}

active_from_output()
{
    echo "$1" | awk '/^CentMgmt::Device:/ {d=$2} /Device HA State/ && tolower($NF)=="active" {sub(/\..*$/, "", d); print d; exit}'
}

append_marker()
{
    echo "$1" >> "$OUT_TMP"
}

run_remote_command()
{
    _remote_cmd="$1"

    rm -f "$CMD_RAW" "$CMD_ERR"

    if [ "$MASTER_OPEN" -eq 0 ]; then
        # Establish the multiplexed connection with the first real MTS command.
        printf 'y\n' | sshpass -e ssh $SSH_OPTS \
            -o ControlMaster=yes \
            -o ControlPath="$CONTROL_SOCKET" \
            -o ControlPersist=60 \
            "$SSH_USER@$MASTER_HOST" \
            "$_remote_cmd" >"$CMD_RAW" 2>"$CMD_ERR"

        _rc=$?

        if [ "$_rc" -eq 0 ]; then
            MASTER_OPEN=1
        fi
    else
        printf 'y\n' | ssh $SSH_OPTS \
            -o BatchMode=yes \
            -S "$CONTROL_SOCKET" \
            "$SSH_USER@$MASTER_HOST" \
            "$_remote_cmd" >"$CMD_RAW" 2>"$CMD_ERR"

        _rc=$?
    fi

    if [ "$_rc" -ne 0 ]; then
        echo "ERROR: Command failed on $MASTER_HOST:"
        echo "       $_remote_cmd"

        if [ -s "$CMD_ERR" ]; then
            cat "$CMD_ERR"
        fi

        return 1
    fi

    return 0
}

run_mts_command()
{
    _display_cmd="$1"
    _remote_cmd="$2"

    echo "Executing: $_display_cmd"
    echo "$_display_cmd" >> "$OUT_TMP"

    run_remote_command "$_remote_cmd" || return 1

    cat "$CMD_RAW" >> "$OUT_TMP"
    echo "" >> "$OUT_TMP"

    return 0
}

run_mts_grep()
{
    _display_cmd="$1"
    _remote_cmd="$2"
    _grep_expr="$3"

    echo "Executing: $_display_cmd"
    echo "$_display_cmd" >> "$OUT_TMP"

    # BIG-IP lands directly in tmsh. Run only the tmsh command remotely,
    # then perform grep locally on the jump server. Keep the displayed
    # command in the MTS output identical to the original manual procedure.
    run_remote_command "$_remote_cmd" || return 1

    grep -E "$_grep_expr" "$CMD_RAW" > "$CMD_TMP"
    _grep_rc=$?

    # grep rc=1 means "no matches", which is not a command failure.
    if [ "$_grep_rc" -gt 1 ]; then
        echo "ERROR: Local grep failed for:"
        echo "       $_display_cmd"
        return 1
    fi

    cat "$CMD_TMP" >> "$OUT_TMP"
    echo "" >> "$OUT_TMP"

    return 0
}

collect_device()
{
    DEVICE="$1"

    CONTROL_SOCKET="/tmp/mtsctl.$$.${HOST_INDEX}"
    PROBE_ERR="/tmp/mts_probe_err.$$.${HOST_INDEX}"
    CMD_RAW="/tmp/mts_cmd_raw.$$.${HOST_INDEX}"
    CMD_TMP="/tmp/mts_cmd.$$.${HOST_INDEX}"
    CMD_ERR="/tmp/mts_cmd_err.$$.${HOST_INDEX}"
    OUT_TMP=""
    OUT_FILE=""
    MASTER_HOST=""
    MASTER_OPEN=0

    echo "Checking HA state on $DEVICE ..."

    ACTIVE_HOST=""
    FIRST_OUTPUT=""
    PEER_OUTPUT=""

    if probe_device "$DEVICE"; then
        FIRST_OUTPUT="$PROBE_OUTPUT"
        DEVICE_STATE=`state_for_host "$DEVICE" "$FIRST_OUTPUT"`

        if [ "$DEVICE_STATE" = "active" ]; then
            ACTIVE_HOST="$DEVICE"
        fi
    else
        echo "Unable to query $DEVICE."
    fi

    # If the supplied hostname follows the usual A/B naming convention,
    # try the opposite unit before falling back to parsing show cm device.
    if [ -z "$ACTIVE_HOST" ]; then
        PEER=`peer_name "$DEVICE"`

        if [ -n "$PEER" ] && [ "`lower_name "$PEER"`" != "`lower_name "$DEVICE"`" ]; then
            echo "Trying peer $PEER ..."

            if probe_device "$PEER"; then
                PEER_OUTPUT="$PROBE_OUTPUT"
                PEER_STATE=`state_for_host "$PEER" "$PEER_OUTPUT"`

                if [ "$PEER_STATE" = "active" ]; then
                    ACTIVE_HOST="$PEER"
                fi
            else
                echo "Unable to query $PEER."
            fi
        fi
    fi

    # Fallback: use show cm device output itself to identify the active member.
    if [ -z "$ACTIVE_HOST" ]; then
        CANDIDATE=""

        if [ -n "$FIRST_OUTPUT" ]; then
            CANDIDATE=`active_from_output "$FIRST_OUTPUT"`
        fi

        if [ -z "$CANDIDATE" ] && [ -n "$PEER_OUTPUT" ]; then
            CANDIDATE=`active_from_output "$PEER_OUTPUT"`
        fi

        if [ -n "$CANDIDATE" ]; then
            echo "show cm device reports active member as $CANDIDATE. Verifying ..."

            if probe_device "$CANDIDATE"; then
                CANDIDATE_STATE=`state_for_host "$CANDIDATE" "$PROBE_OUTPUT"`

                if [ "$CANDIDATE_STATE" = "active" ]; then
                    ACTIVE_HOST="$CANDIDATE"
                fi
            fi
        fi
    fi

    if [ -z "$ACTIVE_HOST" ]; then
        echo "ERROR: Unable to determine the active device for $DEVICE."
        return 1
    fi

    ACTIVE_SHORT=`short_name "$ACTIVE_HOST"`

    echo "Active device: $ACTIVE_SHORT"

    DATE_STR=`date '+%d-%m-%Y'`
    OUT_FILE="${ACTIVE_SHORT}_MTS_${DATE_STR}.txt"
    OUT_FILE=`echo "$OUT_FILE" | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`
    OUT_TMP=".${OUT_FILE}.tmp.$$.${HOST_INDEX}"

    echo "Preparing persistent SSH connection to $ACTIVE_HOST ..."

    MASTER_HOST="$ACTIVE_HOST"
    MASTER_OPEN=0

    : > "$OUT_TMP" || {
        echo "ERROR: Cannot create temporary output file $OUT_TMP."
        return 1
    }

    append_marker "#MTS Generator Commands v1.0"
    echo "" >> "$OUT_TMP"

    append_marker "#Hostname"
    run_mts_command \
        'list sys global-settings hostname' \
        'list sys global-settings hostname' || return 1

    append_marker "#Timestamp"
    run_mts_command \
        'show sys clock' \
        'show sys clock' || return 1

    append_marker "#Get VS Status,current connection,packets in&out"
    run_mts_grep \
        'show ltm virtual raw field-fmt | grep -E "ltm virtual|clientside.pkts|status.availability-state|status.enabled-state|clientside.cur-conns|destination"' \
        'show ltm virtual raw field-fmt' \
        'ltm virtual|clientside\.pkts|status\.availability-state|status\.enabled-state|clientside\.cur-conns|destination' || return 1

    append_marker "#VS to Client & Server Profile"
    run_mts_grep \
        'show ltm virtual detail | grep -E "Ltm::Virtual Server|Ltm::ClientSSL Profile|Ltm::ServerSSL Profile"' \
        'show ltm virtual detail' \
        'Ltm::Virtual Server|Ltm::ClientSSL Profile|Ltm::ServerSSL Profile' || return 1

    append_marker "#Client & Server Profile to Cert"
    run_mts_grep \
        'list ltm profile client-ssl cert | grep -E "ltm profile|cert"' \
        'list ltm profile client-ssl cert' \
        'ltm profile|cert' || return 1

    run_mts_grep \
        'list ltm profile server-ssl cert | grep -E "ltm profile|cert"' \
        'list ltm profile server-ssl cert' \
        'ltm profile|cert' || return 1

    append_marker "#Certificate to Serial"
    run_mts_grep \
        'list sys file ssl-cert all-properties | grep -E "sys file|serial-number"' \
        'list sys file ssl-cert all-properties' \
        'sys file|serial-number' || return 1

    append_marker "#Pools Data"
    run_mts_grep \
        'show ltm virtual detail | grep -E "Ltm::Virtual Server|Ltm::Pool|Ltm::Node"' \
        'show ltm virtual detail' \
        'Ltm::Virtual Server|Ltm::Pool|Ltm::Node' || return 1

    mv "$OUT_TMP" "$OUT_FILE"

    if [ $? -ne 0 ]; then
        echo "ERROR: Unable to create final output file $OUT_FILE."
        return 1
    fi

    OUT_TMP=""

    echo "MTS collection complete: $OUT_FILE"
    return 0
}

# ------------------------------------------------------------
# Main loop
# ------------------------------------------------------------

SUCCESS_COUNT=0
FAIL_COUNT=0
HOST_INDEX=0

while read DEVICE
do
    HOST_INDEX=`expr "$HOST_INDEX" + 1`

    echo ""
    echo "============================================================"
    echo "Host $HOST_INDEX out of $TOTAL_HOSTS: $DEVICE"
    echo "============================================================"

    if collect_device "$DEVICE"; then
        SUCCESS_COUNT=`expr "$SUCCESS_COUNT" + 1`
        echo "Host $HOST_INDEX out of $TOTAL_HOSTS completed successfully."
    else
        FAIL_COUNT=`expr "$FAIL_COUNT" + 1`
        echo "Host $HOST_INDEX out of $TOTAL_HOSTS FAILED: $DEVICE"
    fi

    cleanup_host
done < "$DEVICE_LIST_TMP"

echo ""
echo "============================================================"
echo "MTS collection finished."
echo "Successful: $SUCCESS_COUNT"
echo "Failed:     $FAIL_COUNT"
echo "Total:      $TOTAL_HOSTS"
echo "============================================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
    cleanup_all
    exit 1
fi

cleanup_all
exit 0
