#!/bin/ksh

# BIG-IP certificate usage export.
#
# Remote side:
#   - The SSH account must land directly in tmsh.
#   - Only native tmsh commands are sent over SSH.
#   - No bash, sh, awk, sed, grep, or temporary files are used remotely.
#
# Local side:
#   - All parsing, filtering, correlation, and report generation are performed
#     by this script on the machine from which it is executed.

HOSTS_FILE=${HOSTS_FILE:-hosts.inv}
OUT_FILE=${OUT_FILE:-f5_certificate_usage.tsv}
MIN_DAYS=${MIN_DAYS:-60}

if [ -z "$USER" ]; then
    echo "ERROR: USER is not set." >&2
    exit 1
fi

if [ -z "$SSHPASS" ]; then
    echo "ERROR: export SSHPASS='password' before running the script." >&2
    exit 1
fi

if [ ! -f "$HOSTS_FILE" ]; then
    echo "ERROR: hosts file not found: $HOSTS_FILE" >&2
    exit 1
fi

case "$MIN_DAYS" in
    ''|*[!0-9]*)
        echo "ERROR: MIN_DAYS must be a non-negative integer." >&2
        exit 1
        ;;
esac

NOW_EPOCH=$(date +%s) || exit 1
CUTOFF_EPOCH=$((NOW_EPOCH + MIN_DAYS * 86400))

SSH_OPTS="-o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null \
-o LogLevel=ERROR \
-o ConnectTimeout=15 \
-o PreferredAuthentications=keyboard-interactive,password \
-o KbdInteractiveAuthentication=yes \
-o PubkeyAuthentication=no \
-o NumberOfPasswordPrompts=1"

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/f5-cert-usage.XXXXXX") || {
    echo "ERROR: could not create temporary directory." >&2
    exit 1
}

cleanup()
{
    rm -rf "$WORKDIR"
}
trap cleanup EXIT HUP INT TERM

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    'host' 'cert_name' 'used_by_profile' 'profile_used_by' \
    'expiration_date' 'security_type' 'Organization' 'CN' 'Issuer_CN' \
    > "$OUT_FILE" || exit 1

run_tmsh()
{
    _host=$1
    _command=$2

    # The remote login shell is tmsh. Supplying one "y" answers the initial
    # "Display all N items? (y/n)" question. In a non-interactive SSH session,
    # tmsh then returns the complete output without an interactive page-by-page pager.
    printf 'y\n' | sshpass -e ssh $SSH_OPTS -T "${USER}@${_host}" "${_command}"
}

capture_tmsh()
{
    _host=$1
    _file=$2
    _command=$3

    echo "[$_host] Running tmsh: $_command" >&2
    run_tmsh "$_host" "$_command" > "$_file" 2>&1
    _rc=$?

    if [ $_rc -ne 0 ]; then
        echo "[$_host] ERROR: SSH or tmsh command failed with return code $_rc." >&2
        cat "$_file" >&2
        return 1
    fi

    if grep -Eq 'Syntax Error:|(^|[[:space:]])Error:|^[0-9A-Fa-f]{8}:[0-9]+:' "$_file"; then
        echo "[$_host] ERROR: tmsh reported an error." >&2
        cat "$_file" >&2
        return 1
    fi

    return 0
}

parse_certificates()
{
    awk -v OFS='\t' '
    function trim(s) {
        sub(/^[[:space:]]+/, "", s)
        sub(/[[:space:]]+$/, "", s)
        return s
    }

    function normalize_common(s) {
        s = trim(s)
        if (substr(s, 1, 8) == "/Common/")
            return substr(s, 9)
        if (substr(s, 1, 1) == "/")
            return ""
        return s
    }

    function quoted_value(s) {
        sub(/^[^"]*"/, "", s)
        sub(/"[[:space:]]*$/, "", s)
        return s
    }

    # Extract a DN attribute while preserving commas escaped with a backslash.
    function dn_value(dn, wanted,    i, ch, escaped, part, eq, key, val) {
        part = ""
        escaped = 0

        for (i = 1; i <= length(dn) + 1; i++) {
            ch = (i <= length(dn)) ? substr(dn, i, 1) : ","

            if (escaped) {
                part = part ch
                escaped = 0
                continue
            }

            if (ch == "\\") {
                escaped = 1
                continue
            }

            if (ch != ",") {
                part = part ch
                continue
            }

            part = trim(part)
            eq = index(part, "=")
            if (eq > 0) {
                key = trim(substr(part, 1, eq - 1))
                val = trim(substr(part, eq + 1))
                if (key == wanted)
                    return val
            }
            part = ""
        }

        return ""
    }

    function safe(s) {
        gsub(/[\t\r\n]/, " ", s)
        return s
    }

    function flush() {
        if (!active || name == "")
            return

        print safe(name), safe(exp_epoch), safe(exp_string), \
              safe(dn_value(subject, "O")), safe(dn_value(subject, "CN")), \
              safe(dn_value(issuer, "CN"))
    }

    /^sys file ssl-cert[[:space:]]+/ {
        flush()
        name = normalize_common($4)
        exp_epoch = ""
        exp_string = ""
        subject = ""
        issuer = ""
        active = (name != "")
        next
    }

    active && /^[[:space:]]+expiration-date[[:space:]]+/ {
        exp_epoch = $2
        next
    }

    active && /^[[:space:]]+expiration-string[[:space:]]+/ {
        exp_string = quoted_value($0)
        next
    }

    active && /^[[:space:]]+subject[[:space:]]+"/ {
        subject = quoted_value($0)
        next
    }

    active && /^[[:space:]]+issuer[[:space:]]+"/ {
        issuer = quoted_value($0)
        next
    }

    active && /^}/ {
        flush()
        active = 0
        next
    }

    END {
        flush()
    }
    ' "$1"
}

parse_keys()
{
    awk -v OFS='\t' '
    function trim(s) {
        sub(/^[[:space:]]+/, "", s)
        sub(/[[:space:]]+$/, "", s)
        return s
    }

    function normalize_common(s) {
        s = trim(s)
        if (substr(s, 1, 8) == "/Common/")
            return substr(s, 9)
        if (substr(s, 1, 1) == "/")
            return ""
        return s
    }

    /^sys file ssl-key[[:space:]]+/ {
        key_name = normalize_common($4)
        next
    }

    /^[[:space:]]+security-type[[:space:]]+/ {
        if (key_name != "")
            print key_name, $2
        next
    }
    ' "$1"
}

parse_ssl_profiles()
{
    awk -v OFS='\t' '
    function trim(s) {
        sub(/^[[:space:]]+/, "", s)
        sub(/[[:space:]]+$/, "", s)
        return s
    }

    function normalize_common(s) {
        s = trim(s)
        if (substr(s, 1, 8) == "/Common/")
            return substr(s, 9)
        if (substr(s, 1, 1) == "/")
            return ""
        return s
    }

    function brace_count(s, char,    i, count) {
        count = 0
        for (i = 1; i <= length(s); i++)
            if (substr(s, i, 1) == char)
                count++
        return count
    }

    function emit_pair(cert_name, key_name) {
        cert_name = normalize_common(cert_name)
        key_name = normalize_common(key_name)

        if (profile != "" && cert_name != "" && cert_name != "none")
            print profile_type, profile, cert_name, key_name
    }

    /^ltm profile (client-ssl|server-ssl)[[:space:]]+/ {
        active = 1
        profile_type = $3
        profile = normalize_common($4)
        depth = 1
        direct_cert = ""
        direct_key = ""
        in_cert_chain = 0
        chain_active = 0
        chain_cert = ""
        chain_key = ""
        next
    }

    active {
        line = $0
        text = trim(line)
        old_depth = depth

        if (depth == 1 && text ~ /^cert[[:space:]]+/) {
            split(text, fields, /[[:space:]]+/)
            direct_cert = fields[2]
        } else if (depth == 1 && text ~ /^key[[:space:]]+/) {
            split(text, fields, /[[:space:]]+/)
            direct_key = fields[2]
        }

        if (depth == 1 && text == "cert-key-chain {") {
            in_cert_chain = 1
        } else if (in_cert_chain && depth == 2 && text ~ /[[:space:]]*\{$/) {
            chain_active = 1
            chain_cert = ""
            chain_key = ""
        } else if (chain_active && depth == 3 && text ~ /^cert[[:space:]]+/) {
            split(text, fields, /[[:space:]]+/)
            chain_cert = fields[2]
        } else if (chain_active && depth == 3 && text ~ /^key[[:space:]]+/) {
            split(text, fields, /[[:space:]]+/)
            chain_key = fields[2]
        }

        depth += brace_count(line, "{")
        depth -= brace_count(line, "}")

        if (chain_active && old_depth == 3 && depth == 2) {
            emit_pair(chain_cert, chain_key)
            chain_active = 0
            chain_cert = ""
            chain_key = ""
        }

        if (in_cert_chain && old_depth == 2 && depth == 1)
            in_cert_chain = 0

        if (old_depth == 1 && depth == 0) {
            emit_pair(direct_cert, direct_key)
            active = 0
            profile = ""
        }
    }
    ' "$1"
}

parse_virtual_consumers()
{
    awk -v OFS='\t' '
    function trim(s) {
        sub(/^[[:space:]]+/, "", s)
        sub(/[[:space:]]+$/, "", s)
        return s
    }

    function normalize_common(s) {
        s = trim(s)
        if (substr(s, 1, 8) == "/Common/")
            return substr(s, 9)
        if (substr(s, 1, 1) == "/")
            return ""
        return s
    }

    function brace_count(s, char,    i, count) {
        count = 0
        for (i = 1; i <= length(s); i++)
            if (substr(s, i, 1) == char)
                count++
        return count
    }

    /^ltm virtual[[:space:]]+/ {
        active = 1
        vip = normalize_common($3)
        depth = 1
        in_profiles = 0
        entry_active = 0
        candidate = ""
        next
    }

    active {
        line = $0
        text = trim(line)
        old_depth = depth

        if (depth == 1 && text == "profiles {") {
            in_profiles = 1
        } else if (in_profiles && depth == 2 && text ~ /[[:space:]]*\{$/) {
            split(text, fields, /[[:space:]]+/)
            candidate = normalize_common(fields[1])
            entry_active = (candidate != "")
        } else if (entry_active && depth == 3 && text ~ /^context[[:space:]]+/) {
            if (candidate != "" && vip != "")
                print candidate, "VIP_" vip
        }

        depth += brace_count(line, "{")
        depth -= brace_count(line, "}")

        if (entry_active && old_depth == 3 && depth == 2) {
            entry_active = 0
            candidate = ""
        }

        if (in_profiles && old_depth == 2 && depth == 1)
            in_profiles = 0

        if (old_depth == 1 && depth == 0)
            active = 0
    }
    ' "$1"
}

parse_monitor_consumers()
{
    awk -v OFS='\t' '
    function trim(s) {
        sub(/^[[:space:]]+/, "", s)
        sub(/[[:space:]]+$/, "", s)
        return s
    }

    function normalize_common(s) {
        s = trim(s)
        if (substr(s, 1, 8) == "/Common/")
            return substr(s, 9)
        if (substr(s, 1, 1) == "/")
            return ""
        return s
    }

    /^ltm monitor https[[:space:]]+/ {
        monitor = normalize_common($4)
        next
    }

    /^[[:space:]]+ssl-profile[[:space:]]+/ {
        profile = normalize_common($2)
        if (profile != "" && profile != "none" && monitor != "")
            print profile, "HTTPS_MON_" monitor
        next
    }
    ' "$1"
}

build_host_report()
{
    _host=$1
    _keys=$2
    _profiles=$3
    _consumers=$4
    _certs=$5
    _report=$6

    awk -F '\t' -v OFS='\t' -v host="$_host" -v cutoff="$CUTOFF_EPOCH" '
    function is_default_cert(name) {
        return (name == "default.crt" || name ~ /\/default\.crt$/)
    }

    FILENAME == ARGV[1] {
        key_security[$1] = $2
        next
    }

    FILENAME == ARGV[2] {
        pair_count++
        pair_profile[pair_count] = $2
        pair_cert[pair_count] = $3
        pair_key[pair_count] = $4
        next
    }

    FILENAME == ARGV[3] {
        consumer[$1 SUBSEP $2] = 1
        next
    }

    FILENAME == ARGV[4] {
        cert_exists[$1] = 1
        cert_epoch[$1] = $2
        cert_expiration[$1] = $3
        cert_org[$1] = $4
        cert_cn[$1] = $5
        cert_issuer_cn[$1] = $6
        next
    }

    END {
        for (i = 1; i <= pair_count; i++) {
            profile = pair_profile[i]
            cert = pair_cert[i]
            key = pair_key[i]

            if (!cert_exists[cert])
                continue
            if (is_default_cert(cert))
                continue
            if (cert_epoch[cert] == "" || (cert_epoch[cert] + 0) < cutoff)
                continue

            security = key_security[key]
            if (security == "")
                security = "unknown"

            for (usage in consumer) {
                split(usage, parts, SUBSEP)
                if (parts[1] != profile)
                    continue

                row_key = cert SUBSEP profile SUBSEP parts[2]
                if (printed[row_key]++)
                    continue

                print host, cert, profile, parts[2], cert_expiration[cert], \
                      security, cert_org[cert], cert_cn[cert], cert_issuer_cn[cert]
            }
        }
    }
    ' "$_keys" "$_profiles" "$_consumers" "$_certs" > "$_report"
}

processed=0
failed=0
exported=0
host_index=0

while IFS= read -r host || [ -n "$host" ]
do
    host=$(printf '%s' "$host" | tr -d '\r')

    case "$host" in
        ''|'#'*)
            continue
            ;;
    esac

    host=$(printf '%s\n' "$host" | awk '{print $1}')
    [ -n "$host" ] || continue

    host_index=$((host_index + 1))
    host_dir="$WORKDIR/$host_index"
    mkdir -p "$host_dir" || exit 1

    echo "Processing $host ..." >&2

    cert_raw="$host_dir/certs.raw"
    key_raw="$host_dir/keys.raw"
    client_raw="$host_dir/clientssl.raw"
    server_raw="$host_dir/serverssl.raw"
    vip_raw="$host_dir/virtuals.raw"
    mon_raw="$host_dir/monitors.raw"

    if ! capture_tmsh "$host" "$cert_raw" "cd /Common; list sys file ssl-cert all-properties" ||
       ! capture_tmsh "$host" "$key_raw" "cd /Common; list sys file ssl-key all-properties" ||
       ! capture_tmsh "$host" "$client_raw" "cd /Common; list ltm profile client-ssl" ||
       ! capture_tmsh "$host" "$server_raw" "cd /Common; list ltm profile server-ssl" ||
       ! capture_tmsh "$host" "$vip_raw" "cd /Common; list ltm virtual profiles" ||
       ! capture_tmsh "$host" "$mon_raw" "cd /Common; list ltm monitor https"
    then
        echo "[$host] Skipping host because one or more tmsh commands failed." >&2
        failed=$((failed + 1))
        processed=$((processed + 1))
        continue
    fi

    cert_meta="$host_dir/certs.tsv"
    key_meta="$host_dir/keys.tsv"
    profile_pairs="$host_dir/profile_pairs.tsv"
    consumers="$host_dir/consumers.tsv"
    host_report="$host_dir/report.tsv"

    parse_certificates "$cert_raw" | sort -u > "$cert_meta"
    parse_keys "$key_raw" | sort -u > "$key_meta"

    {
        parse_ssl_profiles "$client_raw"
        parse_ssl_profiles "$server_raw"
    } | sort -u > "$profile_pairs"

    {
        parse_virtual_consumers "$vip_raw"
        parse_monitor_consumers "$mon_raw"
    } | sort -u > "$consumers"

    build_host_report "$host" "$key_meta" "$profile_pairs" "$consumers" "$cert_meta" "$host_report"

    host_rows=$(wc -l < "$host_report" | tr -d ' ')
    cat "$host_report" >> "$OUT_FILE"

    echo "[$host] Exported $host_rows certificate usage row(s)." >&2

    exported=$((exported + host_rows))
    processed=$((processed + 1))
done < "$HOSTS_FILE"

if [ $processed -eq 0 ]; then
    echo "ERROR: no valid hosts found in $HOSTS_FILE" >&2
    exit 1
fi

echo "Completed: $exported row(s) written to $OUT_FILE; $failed host(s) failed." >&2

[ $failed -eq 0 ]
