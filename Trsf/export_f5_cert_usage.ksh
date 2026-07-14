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

printf 'host\tcert_name\tused_by_profile\tprofile_used_by\texpiration_date\tkey_type\tOrganization\tCN\tIssuer_CN\n' > "$OUT_FILE"

while IFS= read -r host || [ -n "$host" ]
do
    host=$(printf '%s' "$host" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$host" in ''|'#'*) continue ;; esac

    echo "Processing $host ..." >&2

    raw=$(sshpass -e ssh $SSH_OPTS "${SSH_USER}@${host}" \
        "bash -s -- '$MIN_DAYS'" 2>&1 <<'REMOTE_SCRIPT'
set -u
set -o pipefail

MIN_DAYS="${1:-60}"
case "$MIN_DAYS" in
    ''|*[!0-9]*) echo "__F5_CERT_AUDIT_ERROR__ invalid MIN_DAYS" >&2; exit 2 ;;
esac

TMPDIR=$(mktemp -d /var/tmp/f5-cert-audit.XXXXXX) || {
    echo "__F5_CERT_AUDIT_ERROR__ cannot create temporary directory" >&2
    exit 2
}

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail()
{
    echo "__F5_CERT_AUDIT_ERROR__ $*" >&2
    exit 1
}

run_tmsh()
{
    section="$1"
    command="$2"

    printf '@@%s\n' "$section" >> "$TMPDIR/all.txt"
    tmsh -a -q -c "cd /Common; $command" >> "$TMPDIR/all.txt" 2> "$TMPDIR/tmsh.err" || {
        cat "$TMPDIR/tmsh.err" >&2
        fail "tmsh command failed: $command"
    }
}

# -q prevents tmsh from asking questions in non-interactive mode.
# No persistent pager/display-threshold preference is changed.
: > "$TMPDIR/all.txt"
run_tmsh CERTS    'list sys file ssl-cert all-properties'
run_tmsh CLIENT   'list ltm profile client-ssl all-properties'
run_tmsh SERVER   'list ltm profile server-ssl all-properties'
run_tmsh VIPS     'list ltm virtual profiles'
run_tmsh MONITORS 'list ltm monitor https all-properties'

cutoff=$(( $(date +%s) + MIN_DAYS * 86400 ))

awk -v cutoff="$cutoff" '
BEGIN { FS=OFS="\t" }

function norm(s) {
    gsub(/^\"|\"$/, "", s)
    sub(/^\/Common\//, "", s)
    return s
}

function dnval(dn,key, n,a,i,p) {
    gsub(/^\"|\"$/, "", dn)
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
        cert[cname]=cexpstr OFS ckey OFS dnval(csubject,"O") OFS dnval(csubject,"CN") OFS dnval(cissuer,"CN")
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
        cexp=cexpstr=ckey=csubject=cissuer=cpart=""
        depth=1
        next
    }

    if(depth>0) {
        line=$0
        text=line
        sub(/^[[:space:]]+/,"",text)

        if(text~/^expiration-date[[:space:]]+/) {
            value=text; sub(/^expiration-date[[:space:]]+/,"",value); cexp=value
        }
        else if(text~/^expiration-string[[:space:]]+/) {
            value=text; sub(/^expiration-string[[:space:]]+/,"",value); gsub(/^\"|\"$/,"",value); cexpstr=value
        }
        else if(text~/^key-type[[:space:]]+/) {
            value=text; sub(/^key-type[[:space:]]+/,"",value); ckey=value
        }
        else if(text~/^subject[[:space:]]+/) {
            value=text; sub(/^subject[[:space:]]+/,"",value); csubject=value
        }
        else if(text~/^issuer[[:space:]]+/) {
            value=text; sub(/^issuer[[:space:]]+/,"",value); cissuer=value
        }
        else if(text~/^partition[[:space:]]+/) {
            value=text; sub(/^partition[[:space:]]+/,"",value); cpart=value
        }

        depth+=braces(line)
        if(depth==0) finish_cert()
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
        depth=1
        next
    }

    if(depth>0) {
        line=$0
        text=line
        sub(/^[[:space:]]+/,"",text)

        if(text~/^cert[[:space:]]+/) {
            value=text
            sub(/^cert[[:space:]]+/,"",value)
            value=norm(value)
            if(value!="" && value!="none")
                profile_cert[ptype SUBSEP pname SUBSEP value]=1
        }
        depth+=braces(line)
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
        for(p in profile_cert) {
            split(p,pa,SUBSEP)
            if(pa[1]==ua[1] && pa[2]==ua[2] && (pa[3] in cert)) {
                split(cert[pa[3]],ci,FS)
                print pa[3],ua[2],ua[3],ci[1],ci[2],ci[3],ci[4],ci[5]
            }
        }
    }
}
' "$TMPDIR/all.txt" \
| LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -k3,3 -u \
> "$TMPDIR/result.tsv" || fail "failed to build report"

echo "__F5_CERT_AUDIT_BEGIN__"
cat "$TMPDIR/result.tsv"
echo "__F5_CERT_AUDIT_END__"
REMOTE_SCRIPT
)
    rc=$?

    if [ $rc -ne 0 ]; then
        echo "ERROR: $host: SSH or remote command failed" >&2
        printf '%s\n' "$raw" >&2
        continue
    fi

    out=$(printf '%s\n' "$raw" | awk '
        /^__F5_CERT_AUDIT_BEGIN__$/ { started=1; next }
        /^__F5_CERT_AUDIT_END__$/   { ended=1; exit }
        started { print }
        END { if(!started || !ended) exit 1 }
    ')
    parse_rc=$?

    if [ $parse_rc -ne 0 ]; then
        echo "ERROR: $host: result markers not found" >&2
        printf '%s\n' "$raw" >&2
        continue
    fi

    if [ -n "$out" ]; then
        printf '%s\n' "$out" | awk -v host="$host" 'BEGIN { OFS="\t" } { print host,$0 }' >> "$OUT_FILE"
    else
        echo "INFO: $host: no matching certificates found" >&2
    fi

done < "$HOSTS_FILE"

echo "Report written to: $OUT_FILE" >&2
