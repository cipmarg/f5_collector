#!/bin/ksh

# Collect F5 rSeries/F5OS host, tenant and FIPS inventory.
# Written for legacy/POSIX awk implementations: no multiline function signatures,
# function calls or conditional expressions.
#
# Usage:
#   ./collect_rseries_inventory_v6_nomore.ksh [hosts_file] [output_file]
#
# Defaults:
#   hosts_file  = hosts.inv
#   output_file = rseries_inventory.tsv
#
# Required environment variables:
#   USER        SSH username
#   SSHPASS     SSH password used by sshpass -e
#
# Optional debugging:
#   DEBUG=1         Keep the raw output of every remote command.
#   SSH_VERBOSE=1   Also keep ssh -vv diagnostics.
#   DEBUG_DIR=path  Override the generated debug-directory name.
#
# Example:
#   DEBUG=1 SSH_VERBOSE=1 ./collect_rseries_inventory_v6_nomore.ksh hosts.inv debug.tsv
#
# Controls:
#   Ctrl+C   Stop the current SSH command and continue processing.
#   Ctrl+\   Terminate the entire script.

HOSTS_FILE=${1:-hosts.inv}
OUTPUT_FILE=${2:-rseries_inventory.tsv}
EXPORT_DATE=$(date '+%Y-%m-%d')
DEBUG=${DEBUG:-0}
SSH_VERBOSE=${SSH_VERBOSE:-0}
DEBUG_DIR=${DEBUG_DIR:-rseries_inventory_debug_$(date '+%Y%m%d_%H%M%S')}

if [ -z "$USER" ]; then
    echo "ERROR: USER is not set." >&2
    exit 1
fi

if [ -z "$SSHPASS" ]; then
    echo "ERROR: SSHPASS is not set." >&2
    exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
    echo "ERROR: sshpass is not available." >&2
    exit 1
fi

if [ ! -r "$HOSTS_FILE" ]; then
    echo "ERROR: Cannot read host file: $HOSTS_FILE" >&2
    exit 1
fi

case "$DEBUG" in
    1|yes|YES|true|TRUE)
        DEBUG=1
        mkdir -p "$DEBUG_DIR" || exit 1
        ;;
    *)
        DEBUG=0
        ;;
esac

case "$SSH_VERBOSE" in
    1|yes|YES|true|TRUE) SSH_VERBOSE=1 ;;
    *) SSH_VERBOSE=0 ;;
esac

TMP_BASE=${TMPDIR:-/tmp}/rseries_inventory.$$
HOSTS_TMP=${TMP_BASE}.hosts
VERSION_TMP=${TMP_BASE}.version
TENANTS_TMP=${TMP_BASE}.tenants
FIPS_TMP=${TMP_BASE}.fips
SSH_ERR_TMP=${TMP_BASE}.ssherr
COMMAND_TMP=${TMP_BASE}.command
ROWS_TMP=${TMP_BASE}.rows
COUNT_TMP=${TMP_BASE}.count

cleanup()
{
    rm -f "$HOSTS_TMP" "$VERSION_TMP" "$TENANTS_TMP" "$FIPS_TMP" \
        "$SSH_ERR_TMP" "$COMMAND_TMP" "$ROWS_TMP" "$COUNT_TMP"
}

CURRENT_HOST=""
CURRENT_COMMAND=""
CURRENT_TAG=""
INTERRUPTED=0
INDEX=0

trap 'cleanup' 0
trap 'INTERRUPTED=1; printf "\nCtrl+C: stopped current SSH command on %s; continuing.\n" "$CURRENT_HOST" >&2' INT
trap 'printf "\nCtrl+\\: terminating script.\n" >&2; trap - 0; cleanup; exit 131' QUIT

# Remove CR characters, blank lines, comments and surrounding whitespace.
sed 's/\r$//; s/^[[:space:]]*//; s/[[:space:]]*$//; /^[[:space:]]*$/d; /^[[:space:]]*#/d' \
    "$HOSTS_FILE" > "$HOSTS_TMP"

TOTAL=$(wc -l < "$HOSTS_TMP" | tr -d ' ')

if [ "$TOTAL" -eq 0 ]; then
    echo "ERROR: No hosts found in $HOSTS_FILE" >&2
    exit 1
fi

printf '"export_date"\t"host"\t"f5os_os_version"\t"f5os_service_version"\t"f5os_product"\t"tenant"\t"mgmt_ip"\t"prefix_length"\t"vcpu_cores_per_node"\t"qat_vf_count"\t"running_state"\t"status"\t"image_version"\t"fips_enabled"\t"fips_occupied_acclr_dev"\t"fips_occupied_contexts"\t"fips_occupied_keys"\t"fips_occupied_partitions"\t"fips_total_acclr_dev"\t"fips_total_contexts"\t"fips_total_keys"\t"fips_total_partitions"\t"fips_status_state"\t"fips_status_desc"\t"fips_partition"\t"fips_partition_keys"\t"fips_partition_accel_devs"\t"fips_partition_backup"\t"fips_partition_state"\t"fips_partition_occupied_session_keys"\t"fips_partition_session_count"\t"fips_partition_pci_address"\t"fips_tenant_pci_device_id"\t"collection_status"\n' \
    > "$OUTPUT_FILE"

save_debug_files()
{
    [ "$DEBUG" -eq 1 ] || return 0

    SAFE_HOST=$(printf '%s' "$CURRENT_HOST" | tr -c 'A-Za-z0-9._-' '_')
    PREFIX=$(printf '%03d_%s_%s' "$INDEX" "$SAFE_HOST" "$CURRENT_TAG")

    cp "$1" "$DEBUG_DIR/${PREFIX}.out" 2>/dev/null
    cp "$SSH_ERR_TMP" "$DEBUG_DIR/${PREFIX}.ssh.log" 2>/dev/null
    cp "$COMMAND_TMP" "$DEBUG_DIR/${PREFIX}.command" 2>/dev/null
}

run_ssh()
{
    SSH_HOST=$1
    SSH_COMMAND=$2
    SSH_OUTPUT=$3

    : > "$SSH_OUTPUT"
    : > "$SSH_ERR_TMP"

    # The F5OS management CLI behaves as an interactive CLI on some releases.
    # Force a pseudo-terminal and feed the command through stdin, matching a
    # normal interactive login. Every show command uses "| nomore" to disable
    # CLI pagination, and "exit" closes the CLI after the command runs.
    printf '%s\nexit\n' "$SSH_COMMAND" > "$COMMAND_TMP"

    if [ "$SSH_VERBOSE" -eq 1 ]; then
        SSHPASS="$SSHPASS" sshpass -e ssh -vv -tt \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=10 \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=2 \
            "$USER@$SSH_HOST" < "$COMMAND_TMP" > "$SSH_OUTPUT" 2> "$SSH_ERR_TMP"
    else
        SSHPASS="$SSHPASS" sshpass -e ssh -tt \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=10 \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=2 \
            "$USER@$SSH_HOST" < "$COMMAND_TMP" > "$SSH_OUTPUT" 2> "$SSH_ERR_TMP"
    fi

    SSH_RC=$?
    save_debug_files "$SSH_OUTPUT"
    return "$SSH_RC"
}

add_status()
{
    if [ "$COLLECTION_STATUS" = "OK" ]; then
        COLLECTION_STATUS=$1
    else
        COLLECTION_STATUS="${COLLECTION_STATUS};$1"
    fi
}

emit_empty_row()
{
    awk \
        -v export_date="$EXPORT_DATE" \
        -v host="$CURRENT_HOST" \
        -v osv="$OS_VERSION" \
        -v sv="$SERVICE_VERSION" \
        -v product="$PRODUCT" \
        -v fips_enabled="$FIPS_ENABLED" \
        -v collect_status="$COLLECTION_STATUS" \
        '
        function clean(value) {
            gsub(/\r/, "", value)
            gsub(/"/, "", value)
            gsub(/\t/, " ", value)
            return value
        }
        BEGIN {
            for (i=1; i<=34; i++) value[i]=""
            value[1]=export_date
            value[2]=host
            value[3]=osv
            value[4]=sv
            value[5]=product
            value[14]=fips_enabled
            value[34]=collect_status
            for (i=1; i<=34; i++) {
                if (i > 1) printf "\t"
                printf "\"%s\"", clean(value[i])
            }
            printf "\n"
        }
        ' >> "$OUTPUT_FILE"
}

while IFS= read CURRENT_HOST
do
    INDEX=$((INDEX + 1))
    echo "[$INDEX/$TOTAL] $CURRENT_HOST"

    : > "$VERSION_TMP"
    : > "$TENANTS_TMP"
    : > "$FIPS_TMP"
    : > "$ROWS_TMP"
    echo 0 > "$COUNT_TMP"

    COLLECTION_STATUS=OK
    FIPS_ENABLED=unknown
    OS_VERSION=""
    SERVICE_VERSION=""
    PRODUCT=""

    CURRENT_COMMAND="show system version | nomore"
    CURRENT_TAG=version
    INTERRUPTED=0
    run_ssh "$CURRENT_HOST" "$CURRENT_COMMAND" "$VERSION_TMP"
    VERSION_RC=$?
    [ "$INTERRUPTED" -eq 1 ] && VERSION_RC=130

    OS_VERSION=$(awk '$1=="system" && $2=="version" && $3=="os-version" {gsub(/\r/,"",$4); print $4; exit}' "$VERSION_TMP")
    SERVICE_VERSION=$(awk '$1=="system" && $2=="version" && $3=="service-version" {gsub(/\r/,"",$4); print $4; exit}' "$VERSION_TMP")
    PRODUCT=$(awk '$1=="system" && $2=="version" && $3=="product" {gsub(/\r/,"",$4); print $4; exit}' "$VERSION_TMP")

    if [ "$VERSION_RC" -ne 0 ]; then
        add_status "VERSION_COMMAND_FAILED"
    elif [ -z "$OS_VERSION" ] && [ -z "$SERVICE_VERSION" ] && [ -z "$PRODUCT" ]; then
        add_status "VERSION_PARSE_FAILED"
    fi

    CURRENT_COMMAND="show tenants | nomore"
    CURRENT_TAG=tenants
    INTERRUPTED=0
    run_ssh "$CURRENT_HOST" "$CURRENT_COMMAND" "$TENANTS_TMP"
    TENANTS_RC=$?
    [ "$INTERRUPTED" -eq 1 ] && TENANTS_RC=130

    CURRENT_COMMAND="show fips | nomore"
    CURRENT_TAG=fips
    INTERRUPTED=0
    run_ssh "$CURRENT_HOST" "$CURRENT_COMMAND" "$FIPS_TMP"
    FIPS_RC=$?
    [ "$INTERRUPTED" -eq 1 ] && FIPS_RC=130

    # A non-FIPS host rejects "show fips". This is an expected result.
    if grep -i \
        -e 'syntax error: element does not exist' \
        -e '%[[:space:]]*Invalid input detected' \
        "$FIPS_TMP" "$SSH_ERR_TMP" >/dev/null 2>&1
    then
        FIPS_ENABLED=no
    elif grep -q '^fips[[:space:]]' "$FIPS_TMP" >/dev/null 2>&1; then
        FIPS_ENABLED=yes
    elif [ "$FIPS_RC" -ne 0 ]; then
        FIPS_ENABLED=unknown
        add_status "FIPS_COMMAND_FAILED"
    else
        FIPS_ENABLED=unknown
        add_status "FIPS_PARSE_FAILED"
    fi

    if [ "$TENANTS_RC" -ne 0 ]; then
        add_status "TENANTS_COMMAND_FAILED"
        emit_empty_row
        continue
    fi

    # The sentinel guarantees that the first AWK input is non-empty, keeping
    # the FNR==NR split reliable even for non-FIPS systems.
    printf '%s\n' '__END_FIPS_OUTPUT__' >> "$FIPS_TMP"

    awk \
        -v export_date="$EXPORT_DATE" \
        -v host="$CURRENT_HOST" \
        -v osv="$OS_VERSION" \
        -v sv="$SERVICE_VERSION" \
        -v product="$PRODUCT" \
        -v fips_enabled="$FIPS_ENABLED" \
        -v collect_status="$COLLECTION_STATUS" \
        -v count_file="$COUNT_TMP" \
        '
        function clear_tenant_values() { tenant=""; mgmt_ip=""; prefix_length=""; vcpu=""; qat=""; running_state=""; tenant_status=""; image_version="" }
        function clean(value) { gsub(/\r/, "", value); gsub(/"/, "", value); gsub(/\t/, " ", value); return value }
        function rest_of_line(start,value,i) { value=""; for (i=start; i<=NF; i++) { if (value != "") value=value " "; value=value $i }; gsub(/\r/, "", value); return value }
        function emit_value(value,first) { if (!first) printf "\t"; printf "\"%s\"", clean(value) }
        function row_status(base,extra) { if (extra == "") return base; if (base == "OK") return extra; return base ";" extra }
        function emit_tenant() {
            if (tenant == "" || running_state != "deployed") return
            tkey=tolower(tenant)
            tpart=tenant_partition[tkey]
            tpci=tenant_pci[tkey]
            extra_status=""
            if (fips_enabled == "yes" && tpart == "") extra_status="FIPS_PARTITION_NOT_FOUND"
            emit_value(export_date,1)
            emit_value(host,0)
            emit_value(osv,0)
            emit_value(sv,0)
            emit_value(product,0)
            emit_value(tenant,0)
            emit_value(mgmt_ip,0)
            emit_value(prefix_length,0)
            emit_value(vcpu,0)
            emit_value(qat,0)
            emit_value(running_state,0)
            emit_value(tenant_status,0)
            emit_value(image_version,0)
            emit_value(fips_enabled,0)
            emit_value(fips_occupied_acclr_dev,0)
            emit_value(fips_occupied_contexts,0)
            emit_value(fips_occupied_keys,0)
            emit_value(fips_occupied_partitions,0)
            emit_value(fips_total_acclr_dev,0)
            emit_value(fips_total_contexts,0)
            emit_value(fips_total_keys,0)
            emit_value(fips_total_partitions,0)
            emit_value(fips_status_state,0)
            emit_value(fips_status_desc,0)
            emit_value(tpart,0)
            emit_value(partition_keys[tpart],0)
            emit_value(partition_accel_devs[tpart],0)
            emit_value(partition_backup[tpart],0)
            emit_value(partition_state[tpart],0)
            emit_value(partition_occupied_session_keys[tpart],0)
            emit_value(partition_session_count[tpart],0)
            emit_value(partition_pci_address[tpart],0)
            emit_value(tpci,0)
            emit_value(row_status(collect_status,extra_status),0)
            printf "\n"
            emitted++
        }
        BEGIN { emitted=0; clear_tenant_values() }
        FNR == NR {
            gsub(/\r/, "")
            if ($1 == "fips" && $2 == "resources") {
                if ($3 == "occupied-acclr-dev") fips_occupied_acclr_dev=$4
                if ($3 == "occupied-contexts") fips_occupied_contexts=$4
                if ($3 == "occupied-keys") fips_occupied_keys=$4
                if ($3 == "occupied-partitions") fips_occupied_partitions=$4
                if ($3 == "total-acclr-dev") fips_total_acclr_dev=$4
                if ($3 == "total-contexts") fips_total_contexts=$4
                if ($3 == "total-keys") fips_total_keys=$4
                if ($3 == "total-partitions") fips_total_partitions=$4
                next
            }
            if ($1 == "fips" && $2 == "status" && $3 == "state") { fips_status_state=$4; next }
            if ($1 == "fips" && $2 == "status" && $3 == "desc") { fips_status_desc=rest_of_line(4); next }
            if (NF >= 8 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && ($4 == "enabled" || $4 == "disabled") && $5 ~ /^-?[0-9]+$/ && $6 ~ /^[0-9]+$/ && $7 ~ /^[0-9]+$/ && $8 ~ /^[A-Za-z0-9]+:[A-Za-z0-9.]+$/) {
                tpartition=$1
                partition_keys[tpartition]=$2
                partition_accel_devs[tpartition]=$3
                partition_backup[tpartition]=$4
                partition_state[tpartition]=$5
                partition_occupied_session_keys[tpartition]=$6
                partition_session_count[tpartition]=$7
                partition_pci_address[tpartition]=$8
                next
            }
            if (NF == 3 && $2 !~ /^[0-9]+$/ && $3 ~ /^[A-Za-z0-9]+:[A-Za-z0-9.]+$/) {
                mapkey=tolower($1)
                tenant_partition[mapkey]=$2
                tenant_pci[mapkey]=$3
                next
            }
            next
        }
        $1 == "tenants" && $2 == "tenant" { emit_tenant(); clear_tenant_values(); tenant=$3; next }
        $1 == "state" && $2 == "mgmt-ip" { mgmt_ip=$3; next }
        $1 == "state" && $2 == "prefix-length" { prefix_length=$3; next }
        $1 == "state" && $2 == "vcpu-cores-per-node" { vcpu=$3; next }
        $1 == "state" && $2 == "qat-vf-count" { qat=$3; next }
        $1 == "state" && $2 == "running-state" { running_state=$3; next }
        $1 == "state" && $2 == "status" { tenant_status=rest_of_line(3); next }
        $1 == "state" && $2 == "image-version" { image_version=rest_of_line(3); next }
        END { emit_tenant(); print emitted > count_file }
        ' "$FIPS_TMP" "$TENANTS_TMP" > "$ROWS_TMP"

    TENANT_COUNT=$(cat "$COUNT_TMP" 2>/dev/null)
    case "$TENANT_COUNT" in
        ''|*[!0-9]*) TENANT_COUNT=0 ;;
    esac

    if [ "$TENANT_COUNT" -gt 0 ]; then
        cat "$ROWS_TMP" >> "$OUTPUT_FILE"
    else
        add_status "NO_DEPLOYED_TENANTS"
        emit_empty_row
    fi

done < "$HOSTS_TMP"

CURRENT_HOST=""
CURRENT_COMMAND=""
CURRENT_TAG=""

echo "Done: $OUTPUT_FILE"
[ "$DEBUG" -eq 1 ] && echo "Debug files: $DEBUG_DIR"

exit 0
