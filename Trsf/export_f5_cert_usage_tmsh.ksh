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

# The remote account's login shell is tmsh. Therefore, commands are sent
# directly to tmsh; neither "bash" nor a nested "tmsh" command is used.
#
# -T prevents allocation of a terminal, so the interactive pager is not used.
# The single "y" on stdin answers the tmsh "Display all N items?" threshold
# question if it is presented. If no question is presented, it is ignored.
SSH_OPTS="-T \
-o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null \
-o LogLevel=ERROR \
-o ConnectTimeout=15 \
-o PreferredAuthentications=keyboard-interactive,password \
-o KbdInteractiveAuthentication=yes \
-o PubkeyAuthentication=no \
-o NumberOfPasswordPrompts=1"

printf 'host\tcert_name\tused_by_profile\tprofile_used_by\texpiration_date\tsecurity_type\tOrganization\tCN\tIssuer_CN\n' > "$OUT_FILE" || {
    echo "ERROR: cannot write output file: $OUT_FILE" >&2
    exit 1
}

TMPROOT=$(mktemp -d "${TMPDIR:-/tmp}/f5-cert-audit.XXXXXX") || {
    echo "ERROR: cannot create temporary directory" >&2
    exit 1
}

cleanup()
{
    rm -rf "$TMPROOT"
}

trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
trap cleanup EXIT

run_remote_tmsh()
{
    section="$1"
    command="$2"
    stdout_file="$HOST_TMP/${section}.out"
    stderr_file="$HOST_TMP/${section}.err"

    # The remote shell is already tmsh. The command executed remotely is
    # equivalent to typing this at the tmsh prompt:
    #     cd /Common; <command>
    printf 'y\n' | sshpass -e ssh $SSH_OPTS "${SSH_USER}@${host}" \
        "cd /Common; ${command}" > "$stdout_file" 2> "$stderr_file"
    rc=$?

    if [ $rc -ne 0 ]; then
        echo "ERROR: $host: tmsh command failed: $command" >&2
        [ -s "$stderr_file" ] && cat "$stderr_file" >&2
        [ -s "$stdout_file" ] && cat "$stdout_file" >&2
        return $rc
    fi

    # Some tmsh errors can be printed in the command output. Treat the common
    # command-parser errors as failures even if SSH itself returned success.
    if grep -E '(^|[[:space:]])Syntax Error:|unexpected argument|was not found|is not a valid' \
        "$stdout_file" >/dev/null 2>&1; then
        echo "ERROR: $host: tmsh reported an error for: $command" >&2
        cat "$stdout_file" >&2
        [ -s "$stderr_file" ] && cat "$stderr_file" >&2
        return 1
    fi

    printf '@@%s\n' "$section" >> "$HOST_TMP/all.txt"
    cat "$stdout_file" >> "$HOST_TMP/all.txt"
    return 0
}

while IFS= read -r host || [ -n "$host" ]
do
    host=$(printf '%s' "$host" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$host" in
        ''|'#'*) continue ;;
    esac

    echo "Processing $host ..." >&2

    HOST_TMP="$TMPROOT/$(printf '%s' "$host" | tr '/:[:space:]' '___')"
    mkdir -p "$HOST_TMP" || {
        echo "ERROR: $host: cannot create host temporary directory" >&2
        continue
    }
    : > "$HOST_TMP/all.txt"

    command_failed=0

    run_remote_tmsh CERTS \
        'list sys file ssl-cert all-properties' || command_failed=1

    [ $command_failed -eq 0 ] && run_remote_tmsh KEYS \
        'list sys file ssl-key all-properties' || command_failed=1

    [ $command_failed -eq 0 ] && run_remote_tmsh CLIENT \
        'list ltm profile client-ssl all-properties' || command_failed=1

    [ $command_failed -eq 0 ] && run_remote_tmsh SERVER \
        'list ltm profile server-ssl all-properties' || command_failed=1

    [ $command_failed -eq 0 ] && run_remote_tmsh VIPS \
        'list ltm virtual profiles' || command_failed=1

    [ $command_failed -eq 0 ] && run_remote_tmsh MONITORS \
        'list ltm monitor https all-properties' || command_failed=1

    if [ $command_failed -ne 0 ]; then
        echo "ERROR: $host: skipped because one or more tmsh commands failed" >&2
        continue
    fi

    cutoff=$(( $(date +%s) + MIN_DAYS * 86400 ))

    awk -v cutoff="$cutoff" '
BEGIN { FS=OFS="\t" }

function norm(s) {
    gsub(/^"|"$/, "", s)
    sub(/^\/Common\//, "", s)
    return s
}

function dnval(dn,key, n,a,i,p) {
    gsub(/^"|"$/, "", dn)
    n=split(dn,a,",")
    p=key "="
    for(i=1;i<=n;i++) {
        sub(/^[[:space:]]+/,"",a[i])
        if(index(a[i],p)==1)
            return substr(a[i],length(p)+1)
    }
    return ""
}

function braces(s, o,c) {
    o=gsub(/\{/,"{",s)
    c=gsub(/\}/,"}",s)
    return o-c
}

function finish_cert() {
    if(cpart=="Common" && cname!="" && cname!="default.crt" && cexp+0>=cutoff)
        cert[cname]=cexpstr OFS dnval(csubject,"O") OFS dnval(csubject,"CN") OFS dnval(cissuer,"CN")
}

function finish_key() {
    if(kpart=="Common" && kname!="")
        key_security[kname]=ksecurity
}

function add_profile_cert_key(type, profile, cert_name, key_name) {
    cert_name=norm(cert_name)
    key_name=norm(key_name)

    if(type!="" && profile!="" && cert_name!="" && cert_name!="none" && \
       key_name!="" && key_name!="none")
        profile_cert_key[type SUBSEP profile SUBSEP cert_name SUBSEP key_name]=1
}

function finish_chain_entry() {
    add_profile_cert_key(ptype,pname,chain_cert,chain_key)
    chain_cert=chain_key=""
}

function finish_profile() {
    add_profile_cert_key(ptype,pname,top_cert,top_key)
    ptype=pname=top_cert=top_key=""
    certkeychain_depth=entry_depth=0
    chain_cert=chain_key=""
}

function finish_vip_profile() {
    if(vprof!="" && vctx=="clientside")
        usage["clientssl" SUBSEP vprof SUBSEP "VIP_" vip]=1
    else if(vprof!="" && vctx=="serverside")
        usage["serverssl" SUBSEP vprof SUBSEP "VIP_" vip]=1
    vprof=vctx=""
}

function finish_monitor() {
    if(mon!="" && mprof!="" && mprof!="none")
        usage["serverssl" SUBSEP mprof SUBSEP "HTTPS_MON_" mon]=1
}

/^@@/ {
    section=substr($0,3)
    depth=0
    next
}

section=="CERTS" {
    if($0 ~ /^sys file ssl-cert[[:space:]]+/) {
        cname=$0
        sub(/^sys file ssl-cert[[:space:]]+/,"",cname)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",cname)
        cname=norm(cname)
        cexp=cexpstr=csubject=cissuer=cpart=""
        depth=1
        next
    }

    if(depth>0) {
        line=$0
        text=line
        sub(/^[[:space:]]+/,"",text)

        if(text~/^expiration-date[[:space:]]+/) {
            value=text
            sub(/^expiration-date[[:space:]]+/,"",value)
            cexp=value
        }
        else if(text~/^expiration-string[[:space:]]+/) {
            value=text
            sub(/^expiration-string[[:space:]]+/,"",value)
            gsub(/^"|"$/,"",value)
            cexpstr=value
        }
        else if(text~/^subject[[:space:]]+/) {
            value=text
            sub(/^subject[[:space:]]+/,"",value)
            csubject=value
        }
        else if(text~/^issuer[[:space:]]+/) {
            value=text
            sub(/^issuer[[:space:]]+/,"",value)
            cissuer=value
        }
        else if(text~/^partition[[:space:]]+/) {
            value=text
            sub(/^partition[[:space:]]+/,"",value)
            cpart=value
        }

        depth+=braces(line)
        if(depth==0) finish_cert()
    }
    next
}

section=="KEYS" {
    if($0 ~ /^sys file ssl-key[[:space:]]+/) {
        kname=$0
        sub(/^sys file ssl-key[[:space:]]+/,"",kname)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",kname)
        kname=norm(kname)
        ksecurity=kpart=""
        depth=1
        next
    }

    if(depth>0) {
        line=$0
        text=line
        sub(/^[[:space:]]+/,"",text)

        if(text~/^security-type[[:space:]]+/) {
            value=text
            sub(/^security-type[[:space:]]+/,"",value)
            ksecurity=value
        }
        else if(text~/^partition[[:space:]]+/) {
            value=text
            sub(/^partition[[:space:]]+/,"",value)
            kpart=value
        }

        depth+=braces(line)
        if(depth==0) finish_key()
    }
    next
}

section=="CLIENT" || section=="SERVER" {
    if($0 ~ /^ltm profile (client-ssl|server-ssl)[[:space:]]+/) {
        ptype=(section=="CLIENT" ? "clientssl" : "serverssl")
        pname=$0
        sub(/^ltm profile (client-ssl|server-ssl)[[:space:]]+/,"",pname)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",pname)
        pname=norm(pname)
        top_cert=top_key=chain_cert=chain_key=""
        certkeychain_depth=entry_depth=0
        depth=1
        next
    }

    if(depth>0) {
        line=$0
        text=line
        sub(/^[[:space:]]+/,"",text)
        before=depth

        if(before==1 && text~/^cert[[:space:]]+/) {
            top_cert=text
            sub(/^cert[[:space:]]+/,"",top_cert)
        }
        else if(before==1 && text~/^key[[:space:]]+/) {
            top_key=text
            sub(/^key[[:space:]]+/,"",top_key)
        }
        else if(before==1 && text=="cert-key-chain {") {
            certkeychain_depth=before+1
        }
        else if(certkeychain_depth>0 && before==certkeychain_depth && \
                text~/[[:space:]]+\{$/) {
            chain_cert=chain_key=""
            entry_depth=before+1
        }
        else if(entry_depth>0 && before==entry_depth && text~/^cert[[:space:]]+/) {
            chain_cert=text
            sub(/^cert[[:space:]]+/,"",chain_cert)
        }
        else if(entry_depth>0 && before==entry_depth && text~/^key[[:space:]]+/) {
            chain_key=text
            sub(/^key[[:space:]]+/,"",chain_key)
        }

        depth+=braces(line)

        if(entry_depth>0 && depth<entry_depth) {
            finish_chain_entry()
            entry_depth=0
        }
        if(certkeychain_depth>0 && depth<certkeychain_depth)
            certkeychain_depth=0
        if(depth==0)
            finish_profile()
    }
    next
}

section=="VIPS" {
    if($0 ~ /^ltm virtual[[:space:]]+/) {
        vip=$0
        sub(/^ltm virtual[[:space:]]+/,"",vip)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",vip)
        vip=norm(vip)
        depth=1
        profiles_depth=0
        vprof=vctx=""
        next
    }

    if(depth>0) {
        line=$0
        text=line
        sub(/^[[:space:]]+/,"",text)
        before=depth

        if(text=="profiles {")
            profiles_depth=before+1
        else if(profiles_depth>0 && before==profiles_depth && text~/[[:space:]]+\{$/) {
            vprof=text
            sub(/[[:space:]]+\{$/,"",vprof)
            vprof=norm(vprof)
            vctx=""
            vprof_depth=before+1
        }
        else if(vprof!="" && text~/^context[[:space:]]+/) {
            vctx=text
            sub(/^context[[:space:]]+/,"",vctx)
        }

        depth+=braces(line)
        if(vprof!="" && depth<vprof_depth) finish_vip_profile()
        if(profiles_depth>0 && depth<profiles_depth) profiles_depth=0
    }
    next
}

section=="MONITORS" {
    if($0 ~ /^ltm monitor https[[:space:]]+/) {
        mon=$0
        sub(/^ltm monitor https[[:space:]]+/,"",mon)
        sub(/[[:space:]]+\{[[:space:]]*$/,"",mon)
        mon=norm(mon)
        mprof=""
        depth=1
        next
    }

    if(depth>0) {
        line=$0
        text=line
        sub(/^[[:space:]]+/,"",text)

        if(text~/^ssl-profile[[:space:]]+/) {
            mprof=text
            sub(/^ssl-profile[[:space:]]+/,"",mprof)
            mprof=norm(mprof)
        }

        depth+=braces(line)
        if(depth==0) finish_monitor()
    }
    next
}

END {
    for(u in usage) {
        split(u,ua,SUBSEP)
        for(p in profile_cert_key) {
            split(p,pa,SUBSEP)
            if(pa[1]==ua[1] && pa[2]==ua[2] && (pa[3] in cert)) {
                split(cert[pa[3]],ci,FS)
                security=(pa[4] in key_security ? key_security[pa[4]] : "")
                print pa[3],ua[2],ua[3],ci[1],security,ci[2],ci[3],ci[4]
            }
        }
    }
}
' "$HOST_TMP/all.txt" > "$HOST_TMP/unsorted.tsv"
    awk_rc=$?

    if [ $awk_rc -ne 0 ]; then
        echo "ERROR: $host: failed to parse tmsh output" >&2
        continue
    fi

    TAB=$(printf '\t')
    LC_ALL=C sort -t "$TAB" -k1,1 -k2,2 -k3,3 -u \
        "$HOST_TMP/unsorted.tsv" > "$HOST_TMP/result.tsv"
    sort_rc=$?

    if [ $sort_rc -ne 0 ]; then
        echo "ERROR: $host: failed to sort report rows" >&2
        continue
    fi

    if [ -s "$HOST_TMP/result.tsv" ]; then
        awk -v host="$host" 'BEGIN { FS=OFS="\t" } { print host,$0 }' \
            "$HOST_TMP/result.tsv" >> "$OUT_FILE"
    else
        echo "INFO: $host: no matching certificates found" >&2
    fi

done < "$HOSTS_FILE"

echo "Report written to: $OUT_FILE" >&2
