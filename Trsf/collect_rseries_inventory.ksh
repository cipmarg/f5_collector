#!/bin/ksh

# Collect F5 rSeries/F5OS host, deployed-tenant and FIPS inventory.
# One SSH session is used per host.
# Written for legacy/POSIX awk implementations.
#
# Usage:
#   ./collect_rseries_inventory_v7_single_session.ksh [hosts_file] [output_file]
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
#   DEBUG=1         Save combined and split command output for every host.
#   SSH_VERBOSE=1   Save ssh -vv diagnostics.
#   DEBUG_DIR=path  Override the generated debug-directory name.
#
# Controls:
#   Ctrl+C   Stop the current host SSH session and continue with the next host.
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
SESSION_RAW_TMP=${TMP_BASE}.session.raw
SESSION_CLEAN_TMP=${TMP_BASE}.session.clean
VERSION_TMP=${TMP_BASE}.version
TENANTS_TMP=${TMP_BASE}.tenants
FIPS_TMP=${TMP_BASE}.fips
SSH_ERR_TMP=${TMP_BASE}.ssherr
COMMAND_TMP=${TMP_BASE}.commands
ROWS_TMP=${TMP_BASE}.rows
COUNT_TMP=${TMP_BASE}.count

cleanup()
{
    rm -f "$HOSTS_TMP" "$SESSION_RAW_TMP" "$SESSION_CLEAN_TMP" \
        "$VERSION_TMP" "$TENANTS_TMP" "$FIPS_TMP" "$SSH_ERR_TMP" \
        "$COMMAND_TMP" "$ROWS_TMP" "$COUNT_TMP"
}

CURRENT_HOST=""
INTERRUPTED=0
INDEX=0

trap 'cleanup' 0
trap 'INTERRUPTED=1; printf "\nCtrl+C: stopped SSH session on %s; continuing.\n" "$CURRENT_HOST" >&2' INT
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

add_status()
{
    if [ "$COLLECTION_STATUS" = "OK" ]; then
        COLLECTION_STATUS=$1
    else
        COLLECTION_STATUS="${COLLECTION_STATUS};$1"
    fi
}

save_debug_files()
{
    [ "$DEBUG" -eq 1 ] || return 0

    SAFE_HOST=$(printf '%s' "$CURRENT_HOST" | tr -c 'A-Za-z0-9._-' '_')
    PREFIX=$(printf '%03d_%s' "$INDEX" "$SAFE_HOST")

    cp "$COMMAND_TMP" "$DEBUG_DIR/${PREFIX}.commands" 2>/dev/null
    cp "$SESSION_RAW_TMP" "$DEBUG_DIR/${PREFIX}.session.raw.out" 2>/dev/null
    cp "$SESSION_CLEAN_TMP" "$DEBUG_DIR/${PREFIX}.session.clean.out" 2>/dev/null
    cp "$VERSION_TMP" "$DEBUG_DIR/${PREFIX}.version.out" 2>/dev/null
    cp "$TENANTS_TMP" "$DEBUG_DIR/${PREFIX}.tenants.out" 2>/dev/null
    cp "$FIPS_TMP" "$DEBUG_DIR/${PREFIX}.fips.out" 2>/dev/null
    cp "$SSH_ERR_TMP" "$DEBUG_DIR/${PREFIX}.ssh.log" 2>/dev/null
}

run_host_session()
{
    SSH_HOST=$1

    : > "$SESSION_RAW_TMP"
    : > "$SESSION_CLEAN_TMP"
    : > "$VERSION_TMP"
    : > "$TENANTS_TMP"
    : > "$FIPS_TMP"
    : > "$SSH_ERR_TMP"

    # All commands run in the same management-CLI session. "nomore" prevents
    # the CLI pager from blocking when a command returns many lines.
    {
        echo 'show system version | nomore'
        echo 'show tenants | nomore'
        echo 'show fips | nomore'
        echo 'exit'
    } > "$COMMAND_TMP"

    if [ "$SSH_VERBOSE" -eq 1 ]; then
        SSHPASS="$SSHPASS" sshpass -e ssh -vv -tt \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=10 \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=2 \
            "$USER@$SSH_HOST" < "$COMMAND_TMP" \
            > "$SESSION_RAW_TMP" 2> "$SSH_ERR_TMP"
    else
        SSHPASS="$SSHPASS" sshpass -e ssh -tt \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=10 \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=2 \
            "$USER@$SSH_HOST" < "$COMMAND_TMP" \
            > "$SESSION_RAW_TMP" 2> "$SSH_ERR_TMP"
    fi

    SSH_RC=$?

    # A forced pseudo-terminal adds carriage returns. Removing them here is
    # essential: otherwise values such as "deployed\r" fail exact comparisons.
    tr -d '\r' < "$SESSION_RAW_TMP" > "$SESSION_CLEAN_TMP"

    # Split the combined session by the command lines echoed by the remote CLI.
    # The content-pattern fallbacks also handle releases with different prompts.
    awk \
        -v version_file="$VERSION_TMP" \
        -v tenants_file="$TENANTS_TMP" \
        -v fips_file="$FIPS_TMP" \
        '
        /#[[:space:]]*show system version[[:space:]]*\|[[:space:]]*nomore/ { section="version"; next }
        /#[[:space:]]*show tenants[[:space:]]*\|[[:space:]]*nomore/ { section="tenants"; next }
        /#[[:space:]]*show fips[[:space:]]*\|[[:space:]]*nomore/ { section="fips"; next }
        section == "" && $1 == "system" && $2 == "version" { section="version" }
        $1 == "tenants" && $2 == "tenant" { section="tenants" }
        $1 == "fips" && ($2 == "resources" || $2 == "status") { section="fips" }
        section == "version" { print > version_file; next }
        section == "tenants" { print > tenants_file; next }
        section == "fips" { print > fips_file; next }
        ' "$SESSION_CLEAN_TMP"

    save_debug_files
    return "$SSH_RC"
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
        function clean(value) { gsub(/"/, "", value); gsub(/\t/, " ", value); return value }
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

    : > "$ROWS_TMP"
    echo 0 > "$COUNT_TMP"

    COLLECTION_STATUS=OK
    FIPS_ENABLED=unknown
    OS_VERSION=""
    SERVICE_VERSION=""
    PRODUCT=""
    INTERRUPTED=0

    run_host_session "$CURRENT_HOST"
    SESSION_RC=$?
    [ "$INTERRUPTED" -eq 1 ] && SESSION_RC=130

    OS_VERSION=$(awk '$1=="system" && $2=="version" && $3=="os-version" { print $4; exit }' "$VERSION_TMP")
    SERVICE_VERSION=$(awk '$1=="system" && $2=="version" && $3=="service-version" { print $4; exit }' "$VERSION_TMP")
    PRODUCT=$(awk '$1=="system" && $2=="version" && $3=="product" { print $4; exit }' "$VERSION_TMP")

    if [ "$SESSION_RC" -ne 0 ]; then
        add_status "SSH_SESSION_FAILED"
    fi

    if [ -z "$OS_VERSION" ] && [ -z "$SERVICE_VERSION" ] && [ -z "$PRODUCT" ]; then
        add_status "VERSION_PARSE_FAILED"
    fi

    if grep -i \
        -e 'syntax error: element does not exist' \
        -e '%[[:space:]]*Invalid input detected' \
        "$FIPS_TMP" >/dev/null 2>&1
    then
        FIPS_ENABLED=no
    elif grep -q '^fips[[:space:]]' "$FIPS_TMP" >/dev/null 2>&1; then
        FIPS_ENABLED=yes
    elif [ -s "$FIPS_TMP" ]; then
        FIPS_ENABLED=unknown
        add_status "FIPS_PARSE_FAILED"
    else
        FIPS_ENABLED=unknown
        add_status "FIPS_OUTPUT_MISSING"
    fi

    if [ ! -s "$TENANTS_TMP" ]; then
        add_status "TENANTS_OUTPUT_MISSING"
        emit_empty_row
        continue
    fi

    # Keep the first input non-empty so that FNR == NR is reliable even when
    # the host is not FIPS-enabled.
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
        function clear_tenant() { tenant=""; mgmt_ip=""; prefix_length=""; vcpu=""; qat=""; running_state=""; tenant_status=""; image_version=""; declared_partition="" }
        function clean(value) { gsub(/"/, "", value); gsub(/\t/, " ", value); return value }
        function rest(start,value,i) { value=""; for (i=start; i<=NF; i++) { if (value != "") value=value " "; value=value $i }; return value }
        function field(value,first) { if (!first) printf "\t"; printf "\"%s\"", clean(value) }
        function combined_status(base,extra) { if (extra == "") return base; if (base == "OK") return extra; return base ";" extra }
        function emit() {
            if (tenant == "" || running_state != "deployed") return
            mapkey=tolower(tenant)
            partition=declared_partition
            if (partition == "") partition=tenant_partition[mapkey]
            tenant_pci_id=tenant_pci[mapkey]
            extra=""
            if (fips_enabled == "yes" && partition == "") extra="FIPS_PARTITION_NOT_FOUND"
            field(export_date,1)
            field(host,0)
            field(osv,0)
            field(sv,0)
            field(product,0)
            field(tenant,0)
            field(mgmt_ip,0)
            field(prefix_length,0)
            field(vcpu,0)
            field(qat,0)
            field(running_state,0)
            field(tenant_status,0)
            field(image_version,0)
            field(fips_enabled,0)
            field(fips_occupied_acclr_dev,0)
            field(fips_occupied_contexts,0)
            field(fips_occupied_keys,0)
            field(fips_occupied_partitions,0)
            field(fips_total_acclr_dev,0)
            field(fips_total_contexts,0)
            field(fips_total_keys,0)
            field(fips_total_partitions,0)
            field(fips_status_state,0)
            field(fips_status_desc,0)
            field(partition,0)
            field(partition_keys[partition],0)
            field(partition_accel_devs[partition],0)
            field(partition_backup[partition],0)
            field(partition_state[partition],0)
            field(partition_occupied_session_keys[partition],0)
            field(partition_session_count[partition],0)
            field(partition_pci_address[partition],0)
            field(tenant_pci_id,0)
            field(combined_status(collect_status,extra),0)
            printf "\n"
            emitted++
        }
        BEGIN { emitted=0; clear_tenant() }
        FNR == NR {
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
            if ($1 == "fips" && $2 == "status" && $3 == "desc") { fips_status_desc=rest(4); next }
            if (NF >= 8 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && ($4 == "enabled" || $4 == "disabled") && $5 ~ /^-?[0-9]+$/ && $6 ~ /^[0-9]+$/ && $7 ~ /^[0-9]+$/ && $8 ~ /^[A-Za-z0-9]+:[A-Za-z0-9.]+$/) {
                p=$1
                partition_keys[p]=$2
                partition_accel_devs[p]=$3
                partition_backup[p]=$4
                partition_state[p]=$5
                partition_occupied_session_keys[p]=$6
                partition_session_count[p]=$7
                partition_pci_address[p]=$8
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
        $1 == "tenants" && $2 == "tenant" { emit(); clear_tenant(); tenant=$3; next }
        $1 == "state" && $2 == "mgmt-ip" { mgmt_ip=$3; next }
        $1 == "state" && $2 == "prefix-length" { prefix_length=$3; next }
        $1 == "state" && $2 == "vcpu-cores-per-node" { vcpu=$3; next }
        $1 == "state" && $2 == "qat-vf-count" { qat=$3; next }
        $1 == "state" && $2 == "running-state" { running_state=$3; next }
        $1 == "state" && $2 == "status" { tenant_status=rest(3); next }
        $1 == "state" && $2 == "image-version" { image_version=rest(3); next }
        $1 == "state" && $2 == "fips-partition" { declared_partition=$3; next }
        END { emit(); print emitted > count_file }
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

echo "Done: $OUTPUT_FILE"
[ "$DEBUG" -eq 1 ] && echo "Debug files: $DEBUG_DIR"

exit 0
