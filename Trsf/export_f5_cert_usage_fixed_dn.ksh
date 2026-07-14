#!/bin/ksh

HOSTS_FILE="${HOSTS_FILE:-hosts.inv}"
OUT_FILE="${OUT_FILE:-f5_certificate_usage.tsv}"
MIN_DAYS="${MIN_DAYS:-60}"
SSH_USER="${USER:-}"

[ -n "$SSH_USER" ] || { echo "ERROR: USER is not set" >&2; exit 1; }
[ -n "${SSHPASS:-}" ] || { echo "ERROR: SSHPASS is not exported" >&2; exit 1; }
[ -f "$HOSTS_FILE" ] || { echo "ERROR: hosts file not found: $HOSTS_FILE" >&2; exit 1; }
command -v sshpass >/dev/null 2>&1 || { echo "ERROR: sshpass is not installed" >&2; exit 1; }

case "$MIN_DAYS" in
    ''|*[!0-9]*) echo "ERROR: MIN_DAYS must be a non-negative integer" >&2; exit 1 ;;
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

TMPROOT=$(mktemp -d /tmp/f5-cert-usage.XXXXXX) || exit 1
trap 'rm -rf "$TMPROOT"' EXIT HUP INT TERM

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    'host' 'cert_name' 'used_by_profile' 'profile_used_by' \
    'expiration_date' 'security_type' 'Organization' 'CN' 'Issuer_CN' \
    > "$OUT_FILE"

run_tmsh()
{
    host="$1"
    command="$2"
    output="$3"

    # The remote login shell is tmsh. All parsing is performed locally.
    printf 'y\n' | sshpass -e ssh $SSH_OPTS "${SSH_USER}@${host}" "$command" \
        > "$output" 2>&1
    rc=$?

    if [ $rc -ne 0 ] || grep -q 'Syntax Error:' "$output"; then
        return 1
    fi

    return 0
}

while IFS= read -r host || [ -n "$host" ]
do
    host=$(printf '%s' "$host" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$host" in ''|'#'*) continue ;; esac

    echo "Processing $host ..." >&2

    hostdir="$TMPROOT/$(printf '%s' "$host" | tr '/:' '__')"
    mkdir -p "$hostdir" || {
        echo "ERROR: $host: cannot create temporary directory" >&2
        continue
    }

    failed=0

    run_tmsh "$host" 'cd /Common; list sys file ssl-cert all-properties' "$hostdir/certs.raw" || failed=1
    [ $failed -eq 0 ] && run_tmsh "$host" 'cd /Common; list sys file ssl-key all-properties' "$hostdir/keys.raw" || failed=1
    [ $failed -eq 0 ] && run_tmsh "$host" 'cd /Common; list ltm profile client-ssl all-properties' "$hostdir/clientssl.raw" || failed=1
    [ $failed -eq 0 ] && run_tmsh "$host" 'cd /Common; list ltm profile server-ssl all-properties' "$hostdir/serverssl.raw" || failed=1
    [ $failed -eq 0 ] && run_tmsh "$host" 'cd /Common; list ltm virtual profiles' "$hostdir/virtuals.raw" || failed=1
    [ $failed -eq 0 ] && run_tmsh "$host" 'cd /Common; list ltm monitor https all-properties' "$hostdir/monitors.raw" || failed=1

    if [ $failed -ne 0 ]; then
        echo "ERROR: $host: SSH or remote tmsh command failed" >&2
        for f in "$hostdir"/*.raw
        do
            [ -s "$f" ] && {
                echo "--- $f ---" >&2
                cat "$f" >&2
            }
        done
        continue
    fi

    {
        echo '@@CERTS@@'
        cat "$hostdir/certs.raw"
        echo '@@KEYS@@'
        cat "$hostdir/keys.raw"
        echo '@@CLIENTSSL@@'
        cat "$hostdir/clientssl.raw"
        echo '@@SERVERSSL@@'
        cat "$hostdir/serverssl.raw"
        echo '@@VIRTUALS@@'
        cat "$hostdir/virtuals.raw"
        echo '@@MONITORS@@'
        cat "$hostdir/monitors.raw"
    } > "$hostdir/all.raw"

    now=$(date +%s) || {
        echo "ERROR: $host: cannot determine local epoch time" >&2
        continue
    }
    cutoff=$((now + MIN_DAYS * 86400))

    awk -v cutoff="$cutoff" '
BEGIN {
    FS = OFS = "\t"
    NOATTR = "\034"
}

function trim(s) {
    sub(/^[[:space:]]+/, "", s)
    sub(/[[:space:]]+$/, "", s)
    return s
}

function unquote(s, n) {
    s = trim(s)
    n = length(s)
    if (n >= 2 && substr(s,1,1) == "\"" && substr(s,n,1) == "\"")
        s = substr(s,2,n-2)
    return s
}

function norm_name(s) {
    s = unquote(s)
    sub(/^\/Common\//, "", s)
    return s
}

# Extract an exact DN attribute. O= cannot be mistaken for OU=.
# Handles quoted or unquoted tmsh output and escaped commas.
function rdn_value(token, wanted, eq, attr, value) {
    token = trim(token)
    eq = index(token, "=")
    if (!eq)
        return NOATTR

    attr = toupper(trim(substr(token,1,eq-1)))
    if (attr != toupper(wanted))
        return NOATTR

    value = trim(substr(token,eq+1))
    gsub(/\\,/, ",", value)
    gsub(/\\=/, "=", value)
    return value
}

function dn_value(dn, wanted, i, ch, token, escaped, value) {
    dn = unquote(dn)
    token = ""
    escaped = 0

    for (i=1; i<=length(dn); i++) {
        ch = substr(dn,i,1)

        if (ch == "," && !escaped) {
            value = rdn_value(token,wanted)
            if (value != NOATTR)
                return value
            token = ""
        }
        else {
            token = token ch
        }

        if (ch == "\\" && !escaped)
            escaped = 1
        else
            escaped = 0
    }

    value = rdn_value(token,wanted)
    return (value == NOATTR ? "" : value)
}

function brace_delta(s, x, opens, closes) {
    x = s
    opens = gsub(/\{/, "", x)
    x = s
    closes = gsub(/\}/, "", x)
    return opens - closes
}

function finish_cert() {
    if ((cpart == "" || cpart == "Common") &&
        cname != "" && cname != "default.crt" && cepoch+0 >= cutoff) {
        cert_ok[cname] = 1
        cert_exp[cname] = cexp
        cert_org[cname] = dn_value(csubject,"O")
        cert_cn[cname] = dn_value(csubject,"CN")
        cert_issuer_cn[cname] = dn_value(cissuer,"CN")
    }
}

function finish_key() {
    if ((kpart == "" || kpart == "Common") && kname != "")
        key_security[kname] = ksecurity
}

function add_profile_pair(type, profile, cert, key, idx) {
    cert = norm_name(cert)
    key = norm_name(key)

    if (cert == "" || cert == "none")
        return

    idx = type SUBSEP profile SUBSEP cert SUBSEP key
    profile_pair[idx] = 1
}

function finish_profile() {
    add_profile_pair(ptype,pname,pdirect_cert,pdirect_key)
    pdirect_cert = pdirect_key = ""
}

function finish_chain_entry() {
    add_profile_pair(ptype,pname,pentry_cert,pentry_key)
    pentry_cert = pentry_key = ""
    pentry_depth = 0
}

function add_vip_usage(profile, context) {
    profile = norm_name(profile)
    context = trim(context)

    if (profile == "" || profile == "none")
        return

    if (context == "clientside")
        usage["clientssl" SUBSEP profile SUBSEP "VIP_" vip] = 1
    else if (context == "serverside")
        usage["serverssl" SUBSEP profile SUBSEP "VIP_" vip] = 1
    else {
        usage["clientssl" SUBSEP profile SUBSEP "VIP_" vip] = 1
        usage["serverssl" SUBSEP profile SUBSEP "VIP_" vip] = 1
    }
}

function finish_vip_entry() {
    add_vip_usage(vprofile,vcontext)
    vprofile = vcontext = ""
    ventry_depth = 0
}

function finish_monitor() {
    mprofile = norm_name(mprofile)
    if (mname != "" && mprofile != "" && mprofile != "none")
        usage["serverssl" SUBSEP mprofile SUBSEP "HTTPS_MON_" mname] = 1
}

/^@@[A-Z]+@@$/ {
    section = substr($0,3,length($0)-4)
    depth = 0
    next
}

section == "CERTS" {
    if ($0 ~ /^sys file ssl-cert[[:space:]]+/) {
        cname = $0
        sub(/^sys file ssl-cert[[:space:]]+/,"",cname)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",cname)
        cname = norm_name(cname)
        cepoch = cexp = csubject = cissuer = cpart = ""
        depth = 1
        next
    }

    if (depth > 0) {
        line = $0
        text = trim(line)

        if (text ~ /^expiration-date[[:space:]]+/) {
            value = text
            sub(/^expiration-date[[:space:]]+/,"",value)
            cepoch = trim(value)
        }
        else if (text ~ /^expiration-string[[:space:]]+/) {
            value = text
            sub(/^expiration-string[[:space:]]+/,"",value)
            cexp = unquote(value)
        }
        else if (text ~ /^subject[[:space:]]+/) {
            value = text
            sub(/^subject[[:space:]]+/,"",value)
            csubject = unquote(value)
        }
        else if (text ~ /^issuer[[:space:]]+/) {
            value = text
            sub(/^issuer[[:space:]]+/,"",value)
            cissuer = unquote(value)
        }
        else if (text ~ /^partition[[:space:]]+/) {
            value = text
            sub(/^partition[[:space:]]+/,"",value)
            cpart = trim(value)
        }

        depth += brace_delta(line)
        if (depth == 0)
            finish_cert()
    }
    next
}

section == "KEYS" {
    if ($0 ~ /^sys file ssl-key[[:space:]]+/) {
        kname = $0
        sub(/^sys file ssl-key[[:space:]]+/,"",kname)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",kname)
        kname = norm_name(kname)
        ksecurity = kpart = ""
        depth = 1
        next
    }

    if (depth > 0) {
        line = $0
        text = trim(line)

        if (text ~ /^security-type[[:space:]]+/) {
            value = text
            sub(/^security-type[[:space:]]+/,"",value)
            ksecurity = trim(value)
        }
        else if (text ~ /^partition[[:space:]]+/) {
            value = text
            sub(/^partition[[:space:]]+/,"",value)
            kpart = trim(value)
        }

        depth += brace_delta(line)
        if (depth == 0)
            finish_key()
    }
    next
}

section == "CLIENTSSL" || section == "SERVERSSL" {
    if ($0 ~ /^ltm profile (client-ssl|server-ssl)[[:space:]]+/) {
        ptype = (section == "CLIENTSSL" ? "clientssl" : "serverssl")
        pname = $0
        sub(/^ltm profile (client-ssl|server-ssl)[[:space:]]+/,"",pname)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",pname)
        pname = norm_name(pname)

        depth = 1
        pchain_depth = pentry_depth = 0
        pdirect_cert = pdirect_key = pentry_cert = pentry_key = ""
        next
    }

    if (depth > 0) {
        line = $0
        text = trim(line)
        before = depth

        if (before == 1 && text == "cert-key-chain {") {
            pchain_depth = before + 1
        }
        else if (pchain_depth > 0 && before == pchain_depth && text ~ /[[:space:]]*\{$/) {
            pentry_depth = before + 1
            pentry_cert = pentry_key = ""
        }
        else if (pentry_depth > 0 && before == pentry_depth && text ~ /^cert[[:space:]]+/) {
            value = text
            sub(/^cert[[:space:]]+/,"",value)
            pentry_cert = value
        }
        else if (pentry_depth > 0 && before == pentry_depth && text ~ /^key[[:space:]]+/) {
            value = text
            sub(/^key[[:space:]]+/,"",value)
            pentry_key = value
        }
        else if (before == 1 && text ~ /^cert[[:space:]]+/) {
            value = text
            sub(/^cert[[:space:]]+/,"",value)
            pdirect_cert = value
        }
        else if (before == 1 && text ~ /^key[[:space:]]+/) {
            value = text
            sub(/^key[[:space:]]+/,"",value)
            pdirect_key = value
        }

        depth += brace_delta(line)

        if (pentry_depth > 0 && depth < pentry_depth)
            finish_chain_entry()
        if (pchain_depth > 0 && depth < pchain_depth)
            pchain_depth = 0
        if (depth == 0)
            finish_profile()
    }
    next
}

section == "VIRTUALS" {
    if ($0 ~ /^ltm virtual[[:space:]]+/) {
        vip = $0
        sub(/^ltm virtual[[:space:]]+/,"",vip)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",vip)
        vip = norm_name(vip)

        depth = 1
        vprofiles_depth = ventry_depth = 0
        vprofile = vcontext = ""
        next
    }

    if (depth > 0) {
        line = $0
        text = trim(line)
        before = depth

        if (before == 1 && text == "profiles {") {
            vprofiles_depth = before + 1
        }
        else if (vprofiles_depth > 0 && before == vprofiles_depth && text ~ /[[:space:]]*\{$/) {
            vprofile = text
            sub(/[[:space:]]*\{$/,"",vprofile)
            vprofile = norm_name(vprofile)
            vcontext = "all"
            ventry_depth = before + 1
        }
        else if (ventry_depth > 0 && before == ventry_depth && text ~ /^context[[:space:]]+/) {
            value = text
            sub(/^context[[:space:]]+/,"",value)
            vcontext = trim(value)
        }

        depth += brace_delta(line)

        if (ventry_depth > 0 && depth < ventry_depth)
            finish_vip_entry()
        if (vprofiles_depth > 0 && depth < vprofiles_depth)
            vprofiles_depth = 0
    }
    next
}

section == "MONITORS" {
    if ($0 ~ /^ltm monitor https[[:space:]]+/) {
        mname = $0
        sub(/^ltm monitor https[[:space:]]+/,"",mname)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",mname)
        mname = norm_name(mname)
        mprofile = ""
        depth = 1
        next
    }

    if (depth > 0) {
        line = $0
        text = trim(line)

        if (text ~ /^ssl-profile[[:space:]]+/) {
            value = text
            sub(/^ssl-profile[[:space:]]+/,"",value)
            mprofile = value
        }

        depth += brace_delta(line)
        if (depth == 0)
            finish_monitor()
    }
    next
}

END {
    for (u in usage) {
        split(u,ua,SUBSEP)
        utype = ua[1]
        uprofile = ua[2]
        usedby = ua[3]

        for (p in profile_pair) {
            split(p,pa,SUBSEP)
            if (pa[1] != utype || pa[2] != uprofile)
                continue

            cert = pa[3]
            key = pa[4]
            if (!(cert in cert_ok))
                continue

            security = (key in key_security ? key_security[key] : "")
            rowkey = cert SUBSEP uprofile SUBSEP usedby SUBSEP cert_exp[cert] SUBSEP \
                     security SUBSEP cert_org[cert] SUBSEP cert_cn[cert] SUBSEP cert_issuer_cn[cert]
            rows[rowkey] = 1
        }
    }

    for (r in rows) {
        split(r,a,SUBSEP)
        print a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]
    }
}
' "$hostdir/all.raw" | LC_ALL=C sort -u > "$hostdir/result.tsv"

    if [ $? -ne 0 ]; then
        echo "ERROR: $host: local parsing failed" >&2
        continue
    fi

    if [ -s "$hostdir/result.tsv" ]; then
        awk -v host="$host" 'BEGIN { FS=OFS="\t" } { print host,$0 }' \
            "$hostdir/result.tsv" >> "$OUT_FILE"
    else
        echo "INFO: $host: no matching certificates found" >&2
    fi

done < "$HOSTS_FILE"

echo "Report written to: $OUT_FILE" >&2
