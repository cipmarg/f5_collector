#!/bin/ksh

HOSTS_FILE="${HOSTS_FILE:-hosts.inv}"
OUT_FILE="${OUT_FILE:-f5_certificate_usage.tsv}"
MIN_DAYS="${MIN_DAYS:-60}"
SSH_USER="${USER:-}"

[ -n "$SSH_USER" ] || {
    echo "ERROR: USER is not set" >&2
    exit 1
}

[ -n "${SSHPASS:-}" ] || {
    echo "ERROR: SSHPASS is not exported" >&2
    exit 1
}

[ -f "$HOSTS_FILE" ] || {
    echo "ERROR: hosts file not found: $HOSTS_FILE" >&2
    exit 1
}

command -v sshpass >/dev/null 2>&1 || {
    echo "ERROR: sshpass is not installed" >&2
    exit 1
}

case "$MIN_DAYS" in
    ''|*[!0-9]*)
        echo "ERROR: MIN_DAYS must be a non-negative integer" >&2
        exit 1
        ;;
esac

SSH_OPTS="-T \
-o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null \
-o LogLevel=ERROR \
-o ConnectTimeout=15 \
-o PreferredAuthentications=keyboard-interactive,password \
-o KbdInteractiveAuthentication=yes \
-o PubkeyAuthentication=no \
-o NumberOfPasswordPrompts=1"

umask 077

TMPROOT=$(mktemp -d /tmp/f5-cert-usage.XXXXXX) || exit 1
trap 'rm -rf "$TMPROOT"' EXIT HUP INT TERM


##############################################################################
# Local certificate parser
##############################################################################

cat > "$TMPROOT/parse_certs.awk" <<'AWK'
BEGIN { FS=OFS="\t"; NOATTR="\034" }

function trim(s) {
    sub(/^[[:space:]]+/, "", s)
    sub(/[[:space:]]+$/, "", s)
    return s
}

function unquote(s,n) {
    s=trim(s)
    n=length(s)
    if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2)
    return s
}

function norm_name(s) {
    s=unquote(s)
    sub(/^\/Common\//, "", s)
    return s
}

function brace_delta(s,x,o,c) {
    x=s
    o=gsub(/\{/, "", x)
    x=s
    c=gsub(/\}/, "", x)
    return o-c
}

function rdn_value(token,wanted,eq,attr,value) {
    token=trim(token)
    eq=index(token,"=")
    if (!eq) return NOATTR
    attr=toupper(trim(substr(token,1,eq-1)))
    if (attr!=toupper(wanted)) return NOATTR
    value=trim(substr(token,eq+1))
    gsub(/\\,/, ",", value)
    gsub(/\\=/, "=", value)
    return value
}

function dn_value(dn,wanted,i,ch,token,escaped,value) {
    dn=unquote(dn)
    token=""
    escaped=0

    for (i=1; i<=length(dn); i++) {
        ch=substr(dn,i,1)

        if (ch=="," && !escaped) {
            value=rdn_value(token,wanted)
            if (value!=NOATTR) return value
            token=""
        } else {
            token=token ch
        }

        if (ch=="\\" && !escaped) escaped=1
        else escaped=0
    }

    value=rdn_value(token,wanted)
    if (value==NOATTR) return ""
    return value
}

function finish_cert() {
    if ((part=="" || part=="Common") && name!="" && name!="default.crt" && epoch+0>=cutoff) {
        print name,expstr,dn_value(subject,"O"),dn_value(subject,"CN"),dn_value(issuer,"CN")
    }
}

/^sys file ssl-cert[[:space:]]+/ {
    name=$0
    sub(/^sys file ssl-cert[[:space:]]+/, "", name)
    sub(/[[:space:]]+\{[[:space:]]*$/, "", name)
    name=norm_name(name)

    epoch=""
    expstr=""
    subject=""
    issuer=""
    part=""
    depth=1
    next
}

depth>0 {
    line=$0
    text=trim(line)

    if (text~/^expiration-date[[:space:]]+/) {
        value=text
        sub(/^expiration-date[[:space:]]+/, "", value)
        epoch=trim(value)
    } else if (text~/^expiration-string[[:space:]]+/) {
        value=text
        sub(/^expiration-string[[:space:]]+/, "", value)
        expstr=unquote(value)
    } else if (text~/^subject[[:space:]]+/) {
        value=text
        sub(/^subject[[:space:]]+/, "", value)
        subject=unquote(value)
    } else if (text~/^issuer[[:space:]]+/) {
        value=text
        sub(/^issuer[[:space:]]+/, "", value)
        issuer=unquote(value)
    } else if (text~/^partition[[:space:]]+/) {
        value=text
        sub(/^partition[[:space:]]+/, "", value)
        part=trim(value)
    }

    depth+=brace_delta(line)
    if (depth==0) finish_cert()
    next
}
AWK


##############################################################################
# Local private-key parser
##############################################################################

cat > "$TMPROOT/parse_keys.awk" <<'AWK'
BEGIN { FS=OFS="\t" }

function trim(s) {
    sub(/^[[:space:]]+/, "", s)
    sub(/[[:space:]]+$/, "", s)
    return s
}

function unquote(s,n) {
    s=trim(s)
    n=length(s)
    if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2)
    return s
}

function norm_name(s) {
    s=unquote(s)
    sub(/^\/Common\//, "", s)
    return s
}

function brace_delta(s,x,o,c) {
    x=s
    o=gsub(/\{/, "", x)
    x=s
    c=gsub(/\}/, "", x)
    return o-c
}

function finish_key() {
    if ((part=="" || part=="Common") && name!="") print name,security
}

/^sys file ssl-key[[:space:]]+/ {
    name=$0
    sub(/^sys file ssl-key[[:space:]]+/, "", name)
    sub(/[[:space:]]+\{[[:space:]]*$/, "", name)
    name=norm_name(name)

    security=""
    part=""
    depth=1
    next
}

depth>0 {
    line=$0
    text=trim(line)

    if (text~/^security-type[[:space:]]+/) {
        value=text
        sub(/^security-type[[:space:]]+/, "", value)
        security=trim(value)
    } else if (text~/^partition[[:space:]]+/) {
        value=text
        sub(/^partition[[:space:]]+/, "", value)
        part=trim(value)
    }

    depth+=brace_delta(line)
    if (depth==0) finish_key()
    next
}
AWK


##############################################################################
# Local client/server SSL profile parser
##############################################################################

cat > "$TMPROOT/parse_profiles.awk" <<'AWK'
BEGIN { FS=OFS="\t" }

function trim(s) {
    sub(/^[[:space:]]+/, "", s)
    sub(/[[:space:]]+$/, "", s)
    return s
}

function unquote(s,n) {
    s=trim(s)
    n=length(s)
    if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2)
    return s
}

function norm_name(s) {
    s=unquote(s)
    sub(/^\/Common\//, "", s)
    return s
}

function brace_delta(s,x,o,c) {
    x=s
    o=gsub(/\{/, "", x)
    x=s
    c=gsub(/\}/, "", x)
    return o-c
}

function emit_pair(cert,key) {
    cert=norm_name(cert)
    key=norm_name(key)
    if (cert!="" && cert!="none") print ptype,pname,cert,key
}

function finish_entry() {
    emit_pair(entry_cert,entry_key)
    entry_cert=""
    entry_key=""
    entry_depth=0
}

function finish_profile() {
    emit_pair(direct_cert,direct_key)
    direct_cert=""
    direct_key=""
}

/^ltm profile (client-ssl|server-ssl)[[:space:]]+/ {
    pname=$0
    sub(/^ltm profile (client-ssl|server-ssl)[[:space:]]+/, "", pname)
    sub(/[[:space:]]+\{[[:space:]]*$/, "", pname)
    pname=norm_name(pname)

    depth=1
    chain_depth=0
    entry_depth=0
    direct_cert=""
    direct_key=""
    entry_cert=""
    entry_key=""
    next
}

depth>0 {
    line=$0
    text=trim(line)
    before=depth

    if (before==1 && text=="cert-key-chain {") {
        chain_depth=before+1
    } else if (chain_depth>0 && before==chain_depth && text~/[[:space:]]*\{$/) {
        entry_depth=before+1
        entry_cert=""
        entry_key=""
    } else if (entry_depth>0 && before==entry_depth && text~/^cert[[:space:]]+/) {
        value=text
        sub(/^cert[[:space:]]+/, "", value)
        entry_cert=value
    } else if (entry_depth>0 && before==entry_depth && text~/^key[[:space:]]+/) {
        value=text
        sub(/^key[[:space:]]+/, "", value)
        entry_key=value
    } else if (before==1 && text~/^cert[[:space:]]+/) {
        value=text
        sub(/^cert[[:space:]]+/, "", value)
        direct_cert=value
    } else if (before==1 && text~/^key[[:space:]]+/) {
        value=text
        sub(/^key[[:space:]]+/, "", value)
        direct_key=value
    }

    depth+=brace_delta(line)

    if (entry_depth>0 && depth<entry_depth) finish_entry()
    if (chain_depth>0 && depth<chain_depth) chain_depth=0
    if (depth==0) finish_profile()

    next
}
AWK


##############################################################################
# Local virtual-server profile usage parser
##############################################################################

cat > "$TMPROOT/parse_virtuals.awk" <<'AWK'
BEGIN { FS=OFS="\t" }

function trim(s) {
    sub(/^[[:space:]]+/, "", s)
    sub(/[[:space:]]+$/, "", s)
    return s
}

function unquote(s,n) {
    s=trim(s)
    n=length(s)
    if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2)
    return s
}

function norm_name(s) {
    s=unquote(s)
    sub(/^\/Common\//, "", s)
    return s
}

function brace_delta(s,x,o,c) {
    x=s
    o=gsub(/\{/, "", x)
    x=s
    c=gsub(/\}/, "", x)
    return o-c
}

function finish_entry() {
    profile=norm_name(profile)

    if (profile!="" && profile!="none") {
        if (context=="clientside") {
            print "clientssl",profile,"VIP_" vip
        } else if (context=="serverside") {
            print "serverssl",profile,"VIP_" vip
        } else {
            print "clientssl",profile,"VIP_" vip
            print "serverssl",profile,"VIP_" vip
        }
    }

    profile=""
    context="all"
    entry_depth=0
}

/^ltm virtual[[:space:]]+/ {
    vip=$0
    sub(/^ltm virtual[[:space:]]+/, "", vip)
    sub(/[[:space:]]+\{[[:space:]]*$/, "", vip)
    vip=norm_name(vip)

    depth=1
    profiles_depth=0
    entry_depth=0
    profile=""
    context="all"
    next
}

depth>0 {
    line=$0
    text=trim(line)
    before=depth

    if (before==1 && text=="profiles {") {
        profiles_depth=before+1
    } else if (profiles_depth>0 && before==profiles_depth && text~/[[:space:]]*\{$/) {
        profile=text
        sub(/[[:space:]]*\{$/, "", profile)
        profile=norm_name(profile)
        context="all"
        entry_depth=before+1
    } else if (entry_depth>0 && before==entry_depth && text~/^context[[:space:]]+/) {
        value=text
        sub(/^context[[:space:]]+/, "", value)
        context=trim(value)
    }

    depth+=brace_delta(line)

    if (entry_depth>0 && depth<entry_depth) finish_entry()
    if (profiles_depth>0 && depth<profiles_depth) profiles_depth=0

    next
}
AWK


##############################################################################
# Local HTTPS-monitor SSL profile usage parser
##############################################################################

cat > "$TMPROOT/parse_monitors.awk" <<'AWK'
BEGIN { FS=OFS="\t" }

function trim(s) {
    sub(/^[[:space:]]+/, "", s)
    sub(/[[:space:]]+$/, "", s)
    return s
}

function unquote(s,n) {
    s=trim(s)
    n=length(s)
    if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2)
    return s
}

function norm_name(s) {
    s=unquote(s)
    sub(/^\/Common\//, "", s)
    return s
}

function brace_delta(s,x,o,c) {
    x=s
    o=gsub(/\{/, "", x)
    x=s
    c=gsub(/\}/, "", x)
    return o-c
}

function finish_monitor() {
    profile=norm_name(profile)
    if (name!="" && profile!="" && profile!="none") print "serverssl",profile,"HTTPS_MON_" name
}

/^ltm monitor https[[:space:]]+/ {
    name=$0
    sub(/^ltm monitor https[[:space:]]+/, "", name)
    sub(/[[:space:]]+\{[[:space:]]*$/, "", name)
    name=norm_name(name)

    profile=""
    depth=1
    next
}

depth>0 {
    line=$0
    text=trim(line)

    if (text~/^ssl-profile[[:space:]]+/) {
        value=text
        sub(/^ssl-profile[[:space:]]+/, "", value)
        profile=value
    }

    depth+=brace_delta(line)
    if (depth==0) finish_monitor()
    next
}
AWK


##############################################################################
# Local correlation
##############################################################################

cat > "$TMPROOT/join.awk" <<'AWK'
BEGIN { FS=OFS="\t" }

FILENAME==certfile {
    cert_exp[$1]=$2
    cert_org[$1]=$3
    cert_cn[$1]=$4
    cert_issuer[$1]=$5
    next
}

FILENAME==keyfile {
    key_security[$1]=$2
    next
}

FILENAME==profilefile {
    pairs[$1 SUBSEP $2 SUBSEP $3 SUBSEP $4]=1
    next
}

FILENAME==usagefile {
    usages[$1 SUBSEP $2 SUBSEP $3]=1
    next
}

END {
    for (u in usages) {
        split(u,uf,SUBSEP)

        for (p in pairs) {
            split(p,pf,SUBSEP)

            if (pf[1]==uf[1] && pf[2]==uf[2] && (pf[3] in cert_exp)) {
                security=""

                if (pf[4] in key_security) security=key_security[pf[4]]

                row=pf[3] SUBSEP pf[2] SUBSEP uf[3] SUBSEP cert_exp[pf[3]] SUBSEP security SUBSEP cert_org[pf[3]] SUBSEP cert_cn[pf[3]] SUBSEP cert_issuer[pf[3]]
                rows[row]=1
            }
        }
    }

    for (r in rows) {
        split(r,f,SUBSEP)
        print f[1],f[2],f[3],f[4],f[5],f[6],f[7],f[8]
    }
}
AWK


##############################################################################
# Output header
##############################################################################

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    'host' \
    'cert_name' \
    'used_by_profile' \
    'profile_used_by' \
    'expiration_date' \
    'security_type' \
    'Organization' \
    'CN' \
    'Issuer_CN' \
    > "$OUT_FILE"


##############################################################################
# Execute a direct command in the remote tmsh login shell
##############################################################################

run_tmsh()
{
    host="$1"
    tmsh_command="$2"
    output="$3"

    echo "[$host] Running tmsh: $tmsh_command" >&2

    printf 'y\n' |
        sshpass -e ssh $SSH_OPTS "${SSH_USER}@${host}" "$tmsh_command" \
        > "$output" 2>&1

    rc=$?

    if [ $rc -ne 0 ]; then
        return 1
    fi

    if grep 'Syntax Error:' "$output" >/dev/null 2>&1; then
        return 1
    fi

    if grep 'unexpected argument' "$output" >/dev/null 2>&1; then
        return 1
    fi

    return 0
}


##############################################################################
# Main loop
##############################################################################

total_rows=0
failed_hosts=0

while IFS= read -r host || [ -n "$host" ]
do
    host=$(printf '%s' "$host" |
        tr -d '\r' |
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    case "$host" in
        ''|'#'*)
            continue
            ;;
    esac

    echo "Processing $host ..." >&2

    hostdir="$TMPROOT/$(printf '%s' "$host" | tr '/:' '__')"

    mkdir -p "$hostdir" || {
        echo "ERROR: $host: cannot create temporary directory" >&2
        failed_hosts=$((failed_hosts+1))
        continue
    }

    failed=0

    run_tmsh \
        "$host" \
        'cd /Common; list sys file ssl-cert all-properties' \
        "$hostdir/certs.raw" ||
        failed=1

    if [ $failed -eq 0 ]; then
        run_tmsh \
            "$host" \
            'cd /Common; list sys file ssl-key all-properties' \
            "$hostdir/keys.raw" ||
            failed=1
    fi

    if [ $failed -eq 0 ]; then
        run_tmsh \
            "$host" \
            'cd /Common; list ltm profile client-ssl all-properties' \
            "$hostdir/clientssl.raw" ||
            failed=1
    fi

    if [ $failed -eq 0 ]; then
        run_tmsh \
            "$host" \
            'cd /Common; list ltm profile server-ssl all-properties' \
            "$hostdir/serverssl.raw" ||
            failed=1
    fi

    if [ $failed -eq 0 ]; then
        run_tmsh \
            "$host" \
            'cd /Common; list ltm virtual profiles' \
            "$hostdir/virtuals.raw" ||
            failed=1
    fi

    if [ $failed -eq 0 ]; then
        run_tmsh \
            "$host" \
            'cd /Common; list ltm monitor https all-properties' \
            "$hostdir/monitors.raw" ||
            failed=1
    fi

    if [ $failed -ne 0 ]; then
        echo "ERROR: $host: SSH or remote tmsh command failed" >&2

        for file in "$hostdir"/*.raw
        do
            if [ -s "$file" ]; then
                echo "--- $file ---" >&2
                cat "$file" >&2
            fi
        done

        failed_hosts=$((failed_hosts+1))
        continue
    fi

    now=$(date +%s) || {
        echo "ERROR: $host: cannot determine local epoch time" >&2
        failed_hosts=$((failed_hosts+1))
        continue
    }

    cutoff=$((now + MIN_DAYS * 86400))


    ##########################################################################
    # All processing below runs locally
    ##########################################################################

    awk -v cutoff="$cutoff" \
        -f "$TMPROOT/parse_certs.awk" \
        "$hostdir/certs.raw" |
        LC_ALL=C sort -u \
        > "$hostdir/certs.tsv" ||
        failed=1

    awk \
        -f "$TMPROOT/parse_keys.awk" \
        "$hostdir/keys.raw" |
        LC_ALL=C sort -u \
        > "$hostdir/keys.tsv" ||
        failed=1

    awk -v ptype=clientssl \
        -f "$TMPROOT/parse_profiles.awk" \
        "$hostdir/clientssl.raw" \
        > "$hostdir/client_profiles.tsv" ||
        failed=1

    awk -v ptype=serverssl \
        -f "$TMPROOT/parse_profiles.awk" \
        "$hostdir/serverssl.raw" \
        > "$hostdir/server_profiles.tsv" ||
        failed=1

    cat \
        "$hostdir/client_profiles.tsv" \
        "$hostdir/server_profiles.tsv" |
        LC_ALL=C sort -u \
        > "$hostdir/profiles.tsv" ||
        failed=1

    awk \
        -f "$TMPROOT/parse_virtuals.awk" \
        "$hostdir/virtuals.raw" \
        > "$hostdir/vip_usage.tsv" ||
        failed=1

    awk \
        -f "$TMPROOT/parse_monitors.awk" \
        "$hostdir/monitors.raw" \
        > "$hostdir/monitor_usage.tsv" ||
        failed=1

    cat \
        "$hostdir/vip_usage.tsv" \
        "$hostdir/monitor_usage.tsv" |
        LC_ALL=C sort -u \
        > "$hostdir/usage.tsv" ||
        failed=1

    if [ $failed -ne 0 ]; then
        echo "ERROR: $host: local parsing failed" >&2
        failed_hosts=$((failed_hosts+1))
        continue
    fi

    awk \
        -v certfile="$hostdir/certs.tsv" \
        -v keyfile="$hostdir/keys.tsv" \
        -v profilefile="$hostdir/profiles.tsv" \
        -v usagefile="$hostdir/usage.tsv" \
        -f "$TMPROOT/join.awk" \
        "$hostdir/certs.tsv" \
        "$hostdir/keys.tsv" \
        "$hostdir/profiles.tsv" \
        "$hostdir/usage.tsv" |
        LC_ALL=C sort -u \
        > "$hostdir/result.tsv"

    if [ $? -ne 0 ]; then
        echo "ERROR: $host: local correlation failed" >&2
        failed_hosts=$((failed_hosts+1))
        continue
    fi

    host_rows=$(awk 'END { print NR+0 }' "$hostdir/result.tsv")

    if [ "$host_rows" -gt 0 ]; then
        awk -v host="$host" '
            BEGIN { FS=OFS="\t" }
            { print host,$0 }
        ' "$hostdir/result.tsv" >> "$OUT_FILE"

        total_rows=$((total_rows+host_rows))

        echo "[$host] Exported $host_rows certificate usage row(s)." >&2
    else
        echo "[$host] No matching certificates found." >&2
    fi

done < "$HOSTS_FILE"

echo "Completed: $total_rows row(s) written to $OUT_FILE; $failed_hosts host(s) failed." >&2
