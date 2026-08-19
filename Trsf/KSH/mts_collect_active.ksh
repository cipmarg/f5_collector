#!/bin/ksh

# MTS data collector for BIG-IP
# Usage: ./mts_collect.ksh <device>
#
# - Uses $USER as the SSH username.
# - Prompts once for the SSH password.
# - Determines the active unit before collecting.
# - Reuses one SSH TCP connection for all MTS collection commands.
# - Leaves BIG-IP CLI pager/display-threshold preferences unchanged.
# - Feeds "y" to each collection command in case BIG-IP asks to display all items.
# - Writes the MTS section markers and command lines into the output because
#   the MTS VBA parser uses those markers.

if [ $# -ne 1 ]; then
    echo "Usage: $0 <device>"
    exit 1
fi

DEVICE="$1"
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

CONTROL_SOCKET="/tmp/mtsctl.$$"
PROBE_ERR="/tmp/mts_probe_err.$$"
CMD_RAW="/tmp/mts_cmd_raw.$$"
CMD_TMP="/tmp/mts_cmd.$$"
CMD_ERR="/tmp/mts_cmd_err.$$"
OUT_TMP=""
OUT_FILE=""
MASTER_HOST=""
MASTER_OPEN=0
PASS=""
SSHPASS=""

# Keep these options conservative for older jump-server OpenSSH versions.
SSH_OPTS="-o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

cleanup()
{
    if [ "$MASTER_OPEN" -eq 1 ] && [ -n "$MASTER_HOST" ]; then
        ssh $SSH_OPTS -S "$CONTROL_SOCKET" -O exit "$SSH_USER@$MASTER_HOST" >/dev/null 2>&1
    fi

    rm -f "$CONTROL_SOCKET" "$PROBE_ERR" "$CMD_RAW" "$CMD_TMP" "$CMD_ERR"

    if [ -n "$OUT_TMP" ] && [ -f "$OUT_TMP" ]; then
        rm -f "$OUT_TMP"
    fi

    PASS=""
    SSHPASS=""
    export SSHPASS
}

abort_script()
{
    echo
    echo "Aborted."
    cleanup
    exit 130
}

trap 'abort_script' INT TERM HUP
trap 'cleanup; exit 131' QUIT

printf "enter pass for %s: " "$SSH_USER"
stty -echo
read PASS
READ_RC=$?
stty echo
printf "\n"

if [ "$READ_RC" -ne 0 ] || [ -z "$PASS" ]; then
    echo "ERROR: No password entered."
    cleanup
    exit 1
fi

SSHPASS="$PASS"
export SSHPASS

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
    echo "ERROR: Unable to determine the active device."
    cleanup
    exit 1
fi

ACTIVE_SHORT=`short_name "$ACTIVE_HOST"`

echo "Active device: $ACTIVE_SHORT"

OUT_FILE="${ACTIVE_SHORT}_MTS_`date '+%d-%m-%Y'`.txt"
OUT_TMP=".${OUT_FILE}.tmp.$$"

echo "Preparing persistent SSH connection to $ACTIVE_HOST ..."

MASTER_HOST="$ACTIVE_HOST"
MASTER_OPEN=0

: > "$OUT_TMP" || {
    echo "ERROR: Cannot create temporary output file $OUT_TMP."
    cleanup
    exit 1
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
            PASS=""
            SSHPASS=""
            export SSHPASS
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

        cleanup
        exit 1
    fi
}

run_mts_command()
{
    _display_cmd="$1"
    _remote_cmd="$2"

    echo "$_display_cmd" >> "$OUT_TMP"

    run_remote_command "$_remote_cmd"

    cat "$CMD_RAW" >> "$OUT_TMP"
    echo "" >> "$OUT_TMP"
}

run_mts_grep()
{
    _display_cmd="$1"
    _remote_cmd="$2"
    _grep_expr="$3"

    echo "$_display_cmd" >> "$OUT_TMP"

    # IMPORTANT:
    # The BIG-IP account lands directly in tmsh. A pipe character sent as part
    # of the SSH remote command is therefore parsed by tmsh and fails with:
    #   Syntax Error: unexpected argument "|"
    #
    # Run only the tmsh command remotely, then perform grep locally on the
    # jump server. The command written to the MTS output remains identical to
    # the original manual instruction.
    run_remote_command "$_remote_cmd"

    grep -E "$_grep_expr" "$CMD_RAW" > "$CMD_TMP"
    _grep_rc=$?

    if [ "$_grep_rc" -gt 1 ]; then
        echo "ERROR: Local grep failed for:"
        echo "       $_display_cmd"
        cleanup
        exit 1
    fi

    cat "$CMD_TMP" >> "$OUT_TMP"
    echo "" >> "$OUT_TMP"
}

append_marker "#MTS Generator Commands v1.0"
echo "" >> "$OUT_TMP"

append_marker "#Hostname"
run_mts_command \
    'list sys global-settings hostname' \
    'list sys global-settings hostname'

append_marker "#Timestamp"
run_mts_command \
    'show sys clock' \
    'show sys clock'

append_marker "#Get VS Status,current connection,packets in&out"
run_mts_grep \
    'show ltm virtual raw field-fmt | grep -E "ltm virtual|clientside.pkts|status.availability-state|status.enabled-state|clientside.cur-conns|destination"' \
    'show ltm virtual raw field-fmt' \
    'ltm virtual|clientside\.pkts|status\.availability-state|status\.enabled-state|clientside\.cur-conns|destination'

append_marker "#VS to Client & Server Profile"
run_mts_grep \
    'show ltm virtual detail | grep -E "Ltm::Virtual Server|Ltm::ClientSSL Profile|Ltm::ServerSSL Profile"' \
    'show ltm virtual detail' \
    'Ltm::Virtual Server|Ltm::ClientSSL Profile|Ltm::ServerSSL Profile'

append_marker "#Client & Server Profile to Cert"
run_mts_grep \
    'list ltm profile client-ssl cert | grep -E "ltm profile|cert"' \
    'list ltm profile client-ssl cert' \
    'ltm profile|cert'
run_mts_grep \
    'list ltm profile server-ssl cert | grep -E "ltm profile|cert"' \
    'list ltm profile server-ssl cert' \
    'ltm profile|cert'

append_marker "#Certificate to Serial"
run_mts_grep \
    'list sys file ssl-cert all-properties | grep -E "sys file|serial-number"' \
    'list sys file ssl-cert all-properties' \
    'sys file|serial-number'

append_marker "#Pools Data"
run_mts_grep \
    'show ltm virtual detail | grep -E "Ltm::Virtual Server|Ltm::Pool|Ltm::Node"' \
    'show ltm virtual detail' \
    'Ltm::Virtual Server|Ltm::Pool|Ltm::Node'

mv "$OUT_TMP" "$OUT_FILE"

if [ $? -ne 0 ]; then
    echo "ERROR: Unable to create final output file $OUT_FILE."
    cleanup
    exit 1
fi

OUT_TMP=""

echo "MTS collection complete:"
echo "$OUT_FILE"

cleanup
exit 0
