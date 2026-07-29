#!/bin/ksh

# Usage:
#   ./collect_rseries_inventory.ksh [hosts_file] [output_file]
#
# Defaults:
#   hosts_file  = hosts.inv
#   output_file = rseries_inventory.tsv

HOSTS_FILE=${1:-hosts.inv}
OUTPUT_FILE=${2:-rseries_inventory.tsv}

if [ -z "$USER" ]; then
    echo "ERROR: USER is not set." >&2
    exit 1
fi

if [ -z "$SSHPASS" ]; then
    echo "ERROR: SSHPASS is not set." >&2
    exit 1
fi

if [ ! -r "$HOSTS_FILE" ]; then
    echo "ERROR: Cannot read host file: $HOSTS_FILE" >&2
    exit 1
fi

TMP_BASE=${TMPDIR:-/tmp}/rseries_inventory.$$
HOSTS_TMP=${TMP_BASE}.hosts
VERSION_TMP=${TMP_BASE}.version
TENANTS_TMP=${TMP_BASE}.tenants
ROWS_TMP=${TMP_BASE}.rows
COUNT_TMP=${TMP_BASE}.count

cleanup()
{
    rm -f "$HOSTS_TMP" "$VERSION_TMP" "$TENANTS_TMP" "$ROWS_TMP" "$COUNT_TMP"
}

CURRENT_HOST=""
CURRENT_COMMAND=""
INTERRUPTED=0

trap 'cleanup' 0
trap 'INTERRUPTED=1; echo "\nCtrl+C: stopped current SSH command on $CURRENT_HOST; continuing." >&2' INT
trap 'echo "\nCtrl+\\: terminating script." >&2; trap - 0; cleanup; exit 131' QUIT

# Remove blank lines, comments, CR characters and surrounding whitespace.
sed 's/\r$//; s/^[[:space:]]*//; s/[[:space:]]*$//; /^[[:space:]]*$/d; /^[[:space:]]*#/d' \
    "$HOSTS_FILE" > "$HOSTS_TMP"

TOTAL=$(wc -l < "$HOSTS_TMP" | tr -d ' ')

if [ "$TOTAL" -eq 0 ]; then
    echo "ERROR: No hosts found in $HOSTS_FILE" >&2
    exit 1
fi

printf '"host"\t"f5os_os_version"\t"f5os_service_version"\t"f5os_product"\t"tenant"\t"mgmt_ip"\t"prefix_length"\t"vcpu_cores_per_node"\t"qat_vf_count"\t"running_state"\t"status"\t"image_version"\t"collection_status"\n' \
    > "$OUTPUT_FILE"

run_ssh()
{
    SSH_HOST=$1
    SSH_COMMAND=$2
    SSH_OUTPUT=$3

    SSHPASS="$SSHPASS" sshpass -e ssh -n \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=2 \
        "$USER@$SSH_HOST" "$SSH_COMMAND" > "$SSH_OUTPUT"
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
    printf '"%s"\t"%s"\t"%s"\t"%s"\t""\t""\t""\t""\t""\t""\t""\t""\t"%s"\n' \
        "$CURRENT_HOST" "$OS_VERSION" "$SERVICE_VERSION" "$PRODUCT" "$COLLECTION_STATUS" \
        >> "$OUTPUT_FILE"
}

INDEX=0
while IFS= read CURRENT_HOST
do
    INDEX=$((INDEX + 1))
    echo "[$INDEX/$TOTAL] $CURRENT_HOST"

    : > "$VERSION_TMP"
    : > "$TENANTS_TMP"
    : > "$ROWS_TMP"
    echo 0 > "$COUNT_TMP"

    COLLECTION_STATUS=OK

    CURRENT_COMMAND="show system version"
    INTERRUPTED=0
    run_ssh "$CURRENT_HOST" "show system version" "$VERSION_TMP"
    VERSION_RC=$?
    if [ "$INTERRUPTED" -eq 1 ]; then
        VERSION_RC=130
    fi

    OS_VERSION=$(awk '$1=="system" && $2=="version" && $3=="os-version" {print $4; exit}' "$VERSION_TMP")
    SERVICE_VERSION=$(awk '$1=="system" && $2=="version" && $3=="service-version" {print $4; exit}' "$VERSION_TMP")
    PRODUCT=$(awk '$1=="system" && $2=="version" && $3=="product" {print $4; exit}' "$VERSION_TMP")

    if [ "$VERSION_RC" -ne 0 ]; then
        add_status "VERSION_COMMAND_FAILED"
    elif [ -z "$OS_VERSION" ] && [ -z "$SERVICE_VERSION" ]; then
        add_status "VERSION_PARSE_FAILED"
    fi

    CURRENT_COMMAND="show tenants"
    INTERRUPTED=0
    run_ssh "$CURRENT_HOST" "show tenants" "$TENANTS_TMP"
    TENANTS_RC=$?
    if [ "$INTERRUPTED" -eq 1 ]; then
        TENANTS_RC=130
    fi

    if [ "$TENANTS_RC" -ne 0 ]; then
        add_status "TENANTS_COMMAND_FAILED"
        emit_empty_row
        continue
    fi

    awk \
        -v host="$CURRENT_HOST" \
        -v osv="$OS_VERSION" \
        -v sv="$SERVICE_VERSION" \
        -v product="$PRODUCT" \
        -v collect_status="$COLLECTION_STATUS" \
        -v count_file="$COUNT_TMP" \
        '
        function clear_values() {
            tenant=""
            mgmt_ip=""
            prefix_length=""
            vcpu=""
            qat=""
            running_state=""
            tenant_status=""
            image_version=""
        }

        function clean(value) {
            gsub(/\r/, "", value)
            gsub(/"/, "", value)
            gsub(/\t/, " ", value)
            return value
        }

        function emit_tenant() {
            if (tenant != "" && running_state == "deployed") {
                printf "\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\n", \
                    clean(host), clean(osv), clean(sv), clean(product), clean(tenant), \
                    clean(mgmt_ip), clean(prefix_length), clean(vcpu), clean(qat), \
                    clean(running_state), clean(tenant_status), clean(image_version), \
                    clean(collect_status)
                emitted++
            }
        }

        BEGIN {
            emitted=0
            clear_values()
        }

        $1=="tenants" && $2=="tenant" {
            emit_tenant()
            clear_values()
            tenant=$3
            next
        }

        $1=="state" && $2=="mgmt-ip" {
            mgmt_ip=$3
            next
        }

        $1=="state" && $2=="prefix-length" {
            prefix_length=$3
            next
        }

        $1=="state" && $2=="vcpu-cores-per-node" {
            vcpu=$3
            next
        }

        $1=="state" && $2=="qat-vf-count" {
            qat=$3
            next
        }

        $1=="state" && $2=="running-state" {
            running_state=$3
            next
        }

        $1=="state" && $2=="status" {
            tenant_status=$3
            for (i=4; i<=NF; i++) tenant_status=tenant_status " " $i
            next
        }

        $1=="state" && $2=="image-version" {
            image_version=$3
            for (i=4; i<=NF; i++) image_version=image_version " " $i
            next
        }

        END {
            emit_tenant()
            print emitted > count_file
        }
        ' "$TENANTS_TMP" > "$ROWS_TMP"

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

echo "Done: $OUTPUT_FILE"
