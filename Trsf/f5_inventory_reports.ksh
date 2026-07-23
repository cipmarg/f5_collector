#!/bin/ksh

###############################################################################
# F5 certificate usage and virtual-to-pool inventory
#
# Controls:
#   Ctrl+C   Stop the current SSH command and continue with the next host
#   Ctrl+\   Terminate the entire script immediately
###############################################################################

HOSTS_FILE="${HOSTS_FILE:-hosts.inv}"
OUT_FILE="${OUT_FILE:-f5_certificate_usage.tsv}"
VIP_OUT_FILE="${VIP_OUT_FILE:-f5_virtual_pool_mapping.tsv}"
MIN_DAYS="${MIN_DAYS:-60}"
DNS_DELAY="${DNS_DELAY:-0.2}"
SSH_USER="${USER:-}"

SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
[ -n "$SCRIPT_DIR" ] || SCRIPT_DIR="."
DNS_CACHE_FILE="${DNS_CACHE_FILE:-$SCRIPT_DIR/f5_dns_cache.tsv}"

EXPORT_DATE=$(date '+%Y-%m-%d %H:%M:%S') || {
    echo "ERROR: cannot determine the export date" >&2
    exit 1
}

###############################################################################
# Validation
###############################################################################

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

command -v nslookup >/dev/null 2>&1 || {
    echo "ERROR: nslookup is not installed" >&2
    exit 1
}

case "$MIN_DAYS" in
    ''|'-'|*[!0-9-]*|--*|*--*|[0-9]*-*)
        echo "ERROR: MIN_DAYS must be a signed integer" >&2
        exit 1
        ;;
esac

awk -v value="$MIN_DAYS" 'BEGIN { exit !(value ~ /^-?[0-9]+$/) }' </dev/null || {
    echo "ERROR: MIN_DAYS must be a signed integer" >&2
    exit 1
}

awk -v value="$DNS_DELAY" 'BEGIN { exit !(value ~ /^([0-9]+([.][0-9]*)?|[.][0-9]+)$/) }' </dev/null || {
    echo "ERROR: DNS_DELAY must be a non-negative number" >&2
    exit 1
}

umask 077

TMPROOT=$(mktemp -d /tmp/f5-inventory.XXXXXX) || {
    echo "ERROR: cannot create temporary directory" >&2
    exit 1
}

YES_FILE="$TMPROOT/yes.input"
printf 'y\n' > "$YES_FILE" || exit 1

if [ ! -e "$DNS_CACHE_FILE" ]; then
    : > "$DNS_CACHE_FILE" || {
        echo "ERROR: cannot create DNS cache: $DNS_CACHE_FILE" >&2
        rm -rf "$TMPROOT"
        exit 1
    }
fi

[ -r "$DNS_CACHE_FILE" ] && [ -w "$DNS_CACHE_FILE" ] || {
    echo "ERROR: DNS cache is not readable and writable: $DNS_CACHE_FILE" >&2
    rm -rf "$TMPROOT"
    exit 1
}

SSH_OPTS="-T \
-o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null \
-o LogLevel=ERROR \
-o ConnectTimeout=15 \
-o PreferredAuthentications=keyboard-interactive,password \
-o KbdInteractiveAuthentication=yes \
-o PubkeyAuthentication=no \
-o NumberOfPasswordPrompts=1"

HAVE_SETSID=0
command -v setsid >/dev/null 2>&1 && HAVE_SETSID=1

CURRENT_SSH_PID=""
CURRENT_SSH_GROUP=0
CURRENT_HOST=""
CURRENT_COMMAND=""
CURRENT_COMMAND_INTERRUPTED=0
LAST_FAILED_OUTPUT=""
DNS_LOOKUP_COUNT=0

cleanup()
{
    rm -rf "$TMPROOT"
}

kill_current_ssh()
{
    typeset pid="$CURRENT_SSH_PID"

    [ -n "$pid" ] || return 0

    if [ "$CURRENT_SSH_GROUP" -eq 1 ]; then
        kill -TERM -"$pid" >/dev/null 2>&1
    else
        if command -v pkill >/dev/null 2>&1; then
            pkill -TERM -P "$pid" >/dev/null 2>&1
        fi
        kill -TERM "$pid" >/dev/null 2>&1
    fi
}

handle_int()
{
    echo >&2

    if [ -n "$CURRENT_SSH_PID" ]; then
        CURRENT_COMMAND_INTERRUPTED=1
        echo "[$CURRENT_HOST] Ctrl+C received: stopping the current SSH command; this host will be skipped." >&2
        kill_current_ssh
    else
        echo "Ctrl+C received while no SSH command is active; continuing." >&2
    fi
}

handle_quit()
{
    echo >&2
    echo "Ctrl+\\ received: terminating the entire script." >&2
    kill_current_ssh
    trap - EXIT HUP INT QUIT TERM
    cleanup
    exit 131
}

handle_term()
{
    echo >&2
    echo "Termination signal received: terminating the entire script." >&2
    kill_current_ssh
    trap - EXIT HUP INT QUIT TERM
    cleanup
    exit 143
}

trap cleanup EXIT
trap handle_int INT
trap handle_quit QUIT
trap handle_term HUP TERM

###############################################################################
# POSIX AWK parsers
###############################################################################

cat > "$TMPROOT/parse_certs.awk" <<'AWK'
BEGIN { FS=OFS="\t"; NOATTR="\034" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function unquote(s,n) { s=trim(s); n=length(s); if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2); return s }
function norm_name(s) { s=unquote(s); sub(/^\/Common\//, "", s); return s }
function brace_delta(s,x,o,c) { x=s; o=gsub(/\{/, "", x); x=s; c=gsub(/\}/, "", x); return o-c }
function rdn_value(token,wanted,eq,attr,value) { token=trim(token); eq=index(token,"="); if (!eq) return NOATTR; attr=toupper(trim(substr(token,1,eq-1))); if (attr!=toupper(wanted)) return NOATTR; value=trim(substr(token,eq+1)); gsub(/\\,/, ",", value); gsub(/\\=/, "=", value); return value }
function dn_value(dn,wanted,i,ch,token,escaped,value) { dn=unquote(dn); token=""; escaped=0; for (i=1; i<=length(dn); i++) { ch=substr(dn,i,1); if (ch=="," && !escaped) { value=rdn_value(token,wanted); if (value!=NOATTR) return value; token="" } else token=token ch; if (ch=="\\" && !escaped) escaped=1; else escaped=0 } value=rdn_value(token,wanted); if (value==NOATTR) return ""; return value }
function make_cu(created,updated) { created=trim(created); updated=trim(updated); if (created=="none") created=""; if (updated=="none") updated=""; if (created==updated) return created; if (created=="") return updated; if (updated=="") return created; return created "," updated }
function clean_san(s) { s=unquote(s); if (s=="none") return ""; gsub(/DNS:/, "", s); gsub(/,[[:space:]]*/, ",", s); return trim(s) }
function finish_cert() { if ((part=="" || part=="Common") && name!="" && name!="default.crt" && epoch!="" && epoch+0>=cutoff) print name,expstr,serial,make_cu(created,updated),dn_value(subject,"O"),dn_value(subject,"CN"),dn_value(issuer,"CN"),clean_san(san) }
/^sys file ssl-cert[[:space:]]+/ { name=$0; sub(/^sys file ssl-cert[[:space:]]+/, "", name); sub(/[[:space:]]+\{[[:space:]]*$/, "", name); name=norm_name(name); epoch=""; expstr=""; serial=""; created=""; updated=""; subject=""; issuer=""; san=""; part=""; depth=1; next }
depth>0 { line=$0; text=trim(line); if (text~/^expiration-date[[:space:]]+/) { value=text; sub(/^expiration-date[[:space:]]+/, "", value); epoch=trim(value) } else if (text~/^expiration-string[[:space:]]+/) { value=text; sub(/^expiration-string[[:space:]]+/, "", value); expstr=unquote(value) } else if (text~/^serial-number[[:space:]]+/) { value=text; sub(/^serial-number[[:space:]]+/, "", value); serial=unquote(value) } else if (text~/^created-by[[:space:]]+/) { value=text; sub(/^created-by[[:space:]]+/, "", value); created=unquote(value) } else if (text~/^updated-by[[:space:]]+/) { value=text; sub(/^updated-by[[:space:]]+/, "", value); updated=unquote(value) } else if (text~/^subject[[:space:]]+/) { value=text; sub(/^subject[[:space:]]+/, "", value); subject=unquote(value) } else if (text~/^issuer[[:space:]]+/) { value=text; sub(/^issuer[[:space:]]+/, "", value); issuer=unquote(value) } else if (text~/^subject-alternative-name[[:space:]]+/) { value=text; sub(/^subject-alternative-name[[:space:]]+/, "", value); san=unquote(value) } else if (text~/^partition[[:space:]]+/) { value=text; sub(/^partition[[:space:]]+/, "", value); part=trim(value) } depth+=brace_delta(line); if (depth==0) finish_cert(); next }
AWK

cat > "$TMPROOT/parse_keys.awk" <<'AWK'
BEGIN { FS=OFS="\t" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function unquote(s,n) { s=trim(s); n=length(s); if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2); return s }
function norm_name(s) { s=unquote(s); sub(/^\/Common\//, "", s); return s }
function brace_delta(s,x,o,c) { x=s; o=gsub(/\{/, "", x); x=s; c=gsub(/\}/, "", x); return o-c }
function finish_key() { if ((part=="" || part=="Common") && name!="") print name,security }
/^sys file ssl-key[[:space:]]+/ { name=$0; sub(/^sys file ssl-key[[:space:]]+/, "", name); sub(/[[:space:]]+\{[[:space:]]*$/, "", name); name=norm_name(name); security=""; part=""; depth=1; next }
depth>0 { line=$0; text=trim(line); if (text~/^security-type[[:space:]]+/) { value=text; sub(/^security-type[[:space:]]+/, "", value); security=trim(value) } else if (text~/^partition[[:space:]]+/) { value=text; sub(/^partition[[:space:]]+/, "", value); part=trim(value) } depth+=brace_delta(line); if (depth==0) finish_key(); next }
AWK

cat > "$TMPROOT/parse_profiles.awk" <<'AWK'
BEGIN { FS=OFS="\t" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function unquote(s,n) { s=trim(s); n=length(s); if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2); return s }
function norm_name(s) { s=unquote(s); sub(/^\/Common\//, "", s); return s }
function brace_delta(s,x,o,c) { x=s; o=gsub(/\{/, "", x); x=s; c=gsub(/\}/, "", x); return o-c }
function emit_pair(cert,key) { cert=norm_name(cert); key=norm_name(key); if (cert!="" && cert!="none") print ptype,pname,cert,key }
function finish_entry() { emit_pair(entry_cert,entry_key); entry_cert=""; entry_key=""; entry_depth=0 }
function finish_profile() { emit_pair(direct_cert,direct_key); direct_cert=""; direct_key="" }
/^ltm profile (client-ssl|server-ssl)[[:space:]]+/ { pname=$0; sub(/^ltm profile (client-ssl|server-ssl)[[:space:]]+/, "", pname); sub(/[[:space:]]+\{[[:space:]]*$/, "", pname); pname=norm_name(pname); depth=1; chain_depth=0; entry_depth=0; direct_cert=""; direct_key=""; entry_cert=""; entry_key=""; next }
depth>0 { line=$0; text=trim(line); before=depth; if (before==1 && text=="cert-key-chain {") chain_depth=before+1; else if (chain_depth>0 && before==chain_depth && text~/[[:space:]]*\{$/) { entry_depth=before+1; entry_cert=""; entry_key="" } else if (entry_depth>0 && before==entry_depth && text~/^cert[[:space:]]+/) { value=text; sub(/^cert[[:space:]]+/, "", value); entry_cert=value } else if (entry_depth>0 && before==entry_depth && text~/^key[[:space:]]+/) { value=text; sub(/^key[[:space:]]+/, "", value); entry_key=value } else if (before==1 && text~/^cert[[:space:]]+/) { value=text; sub(/^cert[[:space:]]+/, "", value); direct_cert=value } else if (before==1 && text~/^key[[:space:]]+/) { value=text; sub(/^key[[:space:]]+/, "", value); direct_key=value } depth+=brace_delta(line); if (entry_depth>0 && depth<entry_depth) finish_entry(); if (chain_depth>0 && depth<chain_depth) chain_depth=0; if (depth==0) finish_profile(); next }
AWK

cat > "$TMPROOT/parse_virtual_config.awk" <<'AWK'
BEGIN { FS=OFS="\t" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function unquote(s,n) { s=trim(s); n=length(s); if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2); return s }
function norm_name(s) { s=unquote(s); sub(/^\/Common\//, "", s); return s }
function brace_delta(s,x,o,c) { x=s; o=gsub(/\{/, "", x); x=s; c=gsub(/\}/, "", x); return o-c }
function clear_lists(i) { for (i=1; i<=pref_count; i++) { delete pref_name[i]; delete pref_context[i] } for (i=1; i<=rule_count; i++) delete rule_name[i]; pref_count=0; rule_count=0 }
function finish_profile_entry() { pref_count++; pref_name[pref_count]=profile; pref_context[pref_count]=context; profile=""; context="all"; profile_entry_depth=0 }
function finish_virtual(i) { if (mode=="base") print vip,destination,pool; else if (mode=="profiles") for (i=1; i<=pref_count; i++) print vip,pref_context[i],pref_name[i]; else if (mode=="rules") for (i=1; i<=rule_count; i++) print vip,rule_name[i] }
/^ltm virtual[[:space:]]+/ { clear_lists(); vip=$0; sub(/^ltm virtual[[:space:]]+/, "", vip); sub(/[[:space:]]+\{[[:space:]]*$/, "", vip); vip=norm_name(vip); destination=""; pool=""; depth=1; profiles_depth=0; profile_entry_depth=0; rules_depth=0; profile=""; context="all"; next }
depth>0 { line=$0; text=trim(line); before=depth; if (before==1 && text~/^destination[[:space:]]+/) { value=text; sub(/^destination[[:space:]]+/, "", value); destination=norm_name(value) } else if (before==1 && text~/^pool[[:space:]]+/) { value=text; sub(/^pool[[:space:]]+/, "", value); pool=norm_name(value); if (pool=="none") pool="" } else if (before==1 && text=="profiles {") profiles_depth=before+1; else if (profiles_depth>0 && before==profiles_depth && text~/[[:space:]]*\{$/) { profile=text; sub(/[[:space:]]*\{$/, "", profile); profile=norm_name(profile); context="all"; profile_entry_depth=before+1 } else if (profile_entry_depth>0 && before==profile_entry_depth && text~/^context[[:space:]]+/) { value=text; sub(/^context[[:space:]]+/, "", value); context=trim(value) } else if (before==1 && text=="rules {") rules_depth=before+1; else if (rules_depth>0 && before==rules_depth && text!="}" && text!="") { rule_count++; rule_name[rule_count]=norm_name(text) } depth+=brace_delta(line); if (profile_entry_depth>0 && depth<profile_entry_depth) finish_profile_entry(); if (profiles_depth>0 && depth<profiles_depth) profiles_depth=0; if (rules_depth>0 && depth<rules_depth) rules_depth=0; if (depth==0) finish_virtual(); next }
AWK

cat > "$TMPROOT/parse_virtual_stats.awk" <<'AWK'
BEGIN { FS=OFS="\t" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function norm_name(s) { s=trim(s); sub(/^\/Common\//, "", s); return s }
function brace_delta(s,x,o,c) { x=s; o=gsub(/\{/, "", x); x=s; c=gsub(/\}/, "", x); return o-c }
function add_extra(k,v) { if (extra=="") extra=k "=" v; else extra=extra "," k "=" v }
function finish_virtual() { print vip,destination,bitsin,bitsout,curconns,maxconns,totconns,availability,enabled,reason,extra }
/^ltm virtual[[:space:]]+/ { vip=$0; sub(/^ltm virtual[[:space:]]+/, "", vip); sub(/[[:space:]]+\{[[:space:]]*$/, "", vip); vip=norm_name(vip); destination=""; bitsin=""; bitsout=""; curconns=""; maxconns=""; totconns=""; availability=""; enabled=""; reason=""; extra=""; depth=1; next }
depth>0 { line=$0; text=trim(line); if (text!="" && text!="}") { key=text; sub(/[[:space:]].*$/, "", key); value=text; sub(/^[^[:space:]]+[[:space:]]*/, "", value); if (key=="destination") destination=value; else if (key=="clientside.bits-in") bitsin=value; else if (key=="clientside.bits-out") bitsout=value; else if (key=="clientside.cur-conns") curconns=value; else if (key=="clientside.max-conns") maxconns=value; else if (key=="clientside.tot-conns") totconns=value; else if (key=="status.availability-state") availability=value; else if (key=="status.enabled-state") enabled=value; else if (key=="status.status-reason") reason=value; else if (key~/^status[.]/) add_extra(key,value) } depth+=brace_delta(line); if (depth==0) finish_virtual(); next }
AWK

cat > "$TMPROOT/parse_monitors.awk" <<'AWK'
BEGIN { FS=OFS="\t" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function unquote(s,n) { s=trim(s); n=length(s); if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2); return s }
function norm_name(s) { s=unquote(s); sub(/^\/Common\//, "", s); return s }
function brace_delta(s,x,o,c) { x=s; o=gsub(/\{/, "", x); x=s; c=gsub(/\}/, "", x); return o-c }
function finish_monitor() { profile=norm_name(profile); if (name!="" && profile!="" && profile!="none") print name,profile }
/^ltm monitor https[[:space:]]+/ { name=$0; sub(/^ltm monitor https[[:space:]]+/, "", name); sub(/[[:space:]]+\{[[:space:]]*$/, "", name); name=norm_name(name); profile=""; depth=1; next }
depth>0 { line=$0; text=trim(line); if (text~/^ssl-profile[[:space:]]+/) { value=text; sub(/^ssl-profile[[:space:]]+/, "", value); profile=value } depth+=brace_delta(line); if (depth==0) finish_monitor(); next }
AWK

cat > "$TMPROOT/parse_pools.awk" <<'AWK'
BEGIN { FS=OFS="\t" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function unquote(s,n) { s=trim(s); n=length(s); if (n>=2 && substr(s,1,1)=="\"" && substr(s,n,1)=="\"") s=substr(s,2,n-2); return s }
function norm_name(s) { s=unquote(s); sub(/^\/Common\//, "", s); return s }
function brace_delta(s,x,o,c) { x=s; o=gsub(/\{/, "", x); x=s; c=gsub(/\}/, "", x); return o-c }
function clean_monitor(s) { s=unquote(s); gsub(/\/Common\//, "", s); if (s=="none") return ""; return s }
function member_port(s,n,a,p) { s=norm_name(s); if (s~/\]:/) { p=s; sub(/^.*\]:/, "", p); return p } n=split(s,a,":"); if (n>1) return a[n]; n=split(s,a,"[.]"); if (n>1) return a[n]; return "" }
function fallback_ip(s,n,a,p) { s=norm_name(s); if (s~/^\[/) { p=s; sub(/^\[/, "", p); sub(/\].*$/, "", p); return p } n=split(s,a,":"); if (n==2) return a[1]; return "" }
function finish_member() { if (member_ip=="") member_ip=fallback_ip(member_name); if (mode=="members") print pool,member_ip,member_port(member_name),member_state }
function finish_pool() { if (mode=="base") print pool,clean_monitor(monitor) }
/^ltm pool[[:space:]]+/ { pool=$0; sub(/^ltm pool[[:space:]]+/, "", pool); sub(/[[:space:]]+\{[[:space:]]*$/, "", pool); pool=norm_name(pool); monitor=""; depth=1; members_depth=0; member_depth=0; member_name=""; member_ip=""; member_state=""; next }
depth>0 { line=$0; text=trim(line); before=depth; if (before==1 && text~/^monitor[[:space:]]+/) { value=text; sub(/^monitor[[:space:]]+/, "", value); monitor=value } else if (before==1 && text=="members {") members_depth=before+1; else if (members_depth>0 && before==members_depth && text~/[[:space:]]*\{$/) { member_name=text; sub(/[[:space:]]*\{$/, "", member_name); member_name=norm_name(member_name); member_ip=""; member_state=""; member_depth=before+1 } else if (member_depth>0 && before==member_depth && text~/^address[[:space:]]+/) { value=text; sub(/^address[[:space:]]+/, "", value); member_ip=trim(value); sub(/%[0-9]+$/, "", member_ip) } else if (member_depth>0 && before==member_depth && text~/^state[[:space:]]+/) { value=text; sub(/^state[[:space:]]+/, "", value); member_state=trim(value) } depth+=brace_delta(line); if (member_depth>0 && depth<member_depth) { finish_member(); member_depth=0 } if (members_depth>0 && depth<members_depth) members_depth=0; if (depth==0) finish_pool(); next }
AWK

cat > "$TMPROOT/collect_dns_ips.awk" <<'AWK'
BEGIN { FS=OFS="\t" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function destination_ip(s,p,n,a) { s=trim(s); sub(/^\/Common\//, "", s); if (s=="" || s=="none" || s=="*") return ""; if (s~/^\[/) { p=s; sub(/^\[/, "", p); sub(/\].*$/, "", p) } else if (s~/^[0-9][0-9.]*%[0-9]+:/ || s~/^[0-9][0-9.]*:/) { n=split(s,a,":"); p=a[1] } else if (s~/^[0-9][0-9.]*%[0-9]+$/ || s~/^[0-9][0-9.]*$/) p=s; else if (s~/:/ && s~/[.][^.:]+$/) { p=s; sub(/[.][^.:]+$/, "", p) } else p=s; sub(/%[0-9]+$/, "", p); if (p=="0.0.0.0" || p=="::" || p=="*") return ""; return p }
FILENAME==statsfile { ip=destination_ip($2); if (ip!="") print ip; next }
FILENAME==basefile { ip=destination_ip($2); if (ip!="") print ip; next }
FILENAME==membersfile { ip=trim($2); sub(/%[0-9]+$/, "", ip); if (ip!="" && ip!="0.0.0.0" && ip!="::" && ip!="*") print ip; next }
AWK

cat > "$TMPROOT/join_cert_report.awk" <<'AWK'
BEGIN { FS=OFS="\t" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function destination_ip(s,p,n,a) { s=trim(s); sub(/^\/Common\//, "", s); if (s=="" || s=="none" || s=="*") return ""; if (s~/^\[/) { p=s; sub(/^\[/, "", p); sub(/\].*$/, "", p) } else if (s~/^[0-9][0-9.]*%[0-9]+:/ || s~/^[0-9][0-9.]*:/) { n=split(s,a,":"); p=a[1] } else if (s~/^[0-9][0-9.]*%[0-9]+$/ || s~/^[0-9][0-9.]*$/) p=s; else if (s~/:/ && s~/[.][^.:]+$/) { p=s; sub(/[.][^.:]+$/, "", p) } else p=s; sub(/%[0-9]+$/, "", p); if (p=="0.0.0.0" || p=="::" || p=="*") return ""; return p }
FILENAME==certfile { cert_exists[$1]=1; cert_exp[$1]=$2; cert_serial[$1]=$3; cert_cu[$1]=$4; cert_org[$1]=$5; cert_cn[$1]=$6; cert_issuer[$1]=$7; cert_san[$1]=$8; next }
FILENAME==keyfile { key_security[$1]=$2; next }
FILENAME==profilefile { pairs[$1 SUBSEP $2 SUBSEP $3 SUBSEP $4]=1; next }
FILENAME==basefile { configured[$1]=$2; next }
FILENAME==reffile { if ($2=="clientside") usages["clientssl" SUBSEP $3 SUBSEP "VIP_" $1]=1; else if ($2=="serverside") usages["serverssl" SUBSEP $3 SUBSEP "VIP_" $1]=1; else { usages["clientssl" SUBSEP $3 SUBSEP "VIP_" $1]=1; usages["serverssl" SUBSEP $3 SUBSEP "VIP_" $1]=1 } next }
FILENAME==monitorfile { usages["serverssl" SUBSEP $2 SUBSEP "HTTPS_MON_" $1]=1; next }
FILENAME==statsfile { stat_dest[$1]=$2; stat_in[$1]=$3; stat_out[$1]=$4; stat_cur[$1]=$5; stat_max[$1]=$6; stat_tot[$1]=$7; stat_avail[$1]=$8; stat_enabled[$1]=$9; stat_reason[$1]=$10; stat_extra[$1]=$11; next }
FILENAME==dnsfile { dns[$1]=$2; next }
END { for (u in usages) { split(u,uf,SUBSEP); for (p in pairs) { split(p,pf,SUBSEP); if (pf[1]==uf[1] && pf[2]==uf[2] && (pf[3] in cert_exists)) { security=""; if (pf[4] in key_security) security=key_security[pf[4]]; dest=""; resolved=""; bitsin=""; bitsout=""; cur=""; max=""; tot=""; avail=""; enabled=""; reason=""; extra=""; if (substr(uf[3],1,4)=="VIP_") { vip=substr(uf[3],5); dest=stat_dest[vip]; if (dest=="") dest=configured[vip]; ip=destination_ip(dest); if (ip!="") { if (ip in dns) resolved=dns[ip]; else resolved="NR" } bitsin=stat_in[vip]; bitsout=stat_out[vip]; cur=stat_cur[vip]; max=stat_max[vip]; tot=stat_tot[vip]; avail=stat_avail[vip]; enabled=stat_enabled[vip]; reason=stat_reason[vip]; extra=stat_extra[vip] } row=pf[3] SUBSEP pf[2] SUBSEP uf[3] SUBSEP cert_exp[pf[3]] SUBSEP security SUBSEP cert_serial[pf[3]] SUBSEP cert_cu[pf[3]] SUBSEP cert_org[pf[3]] SUBSEP cert_cn[pf[3]] SUBSEP cert_issuer[pf[3]] SUBSEP cert_san[pf[3]] SUBSEP dest SUBSEP resolved SUBSEP bitsin SUBSEP bitsout SUBSEP cur SUBSEP max SUBSEP tot SUBSEP avail SUBSEP enabled SUBSEP reason SUBSEP extra; rows[row]=1 } } } for (r in rows) { split(r,f,SUBSEP); print f[1],f[2],f[3],f[4],f[5],f[6],f[7],f[8],f[9],f[10],f[11],f[12],f[13],f[14],f[15],f[16],f[17],f[18],f[19],f[20],f[21],f[22] } }
AWK

cat > "$TMPROOT/join_flat_report.awk" <<'AWK'
BEGIN { FS=OFS="\t" }
function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
function destination_ip(s,p,n,a) { s=trim(s); sub(/^\/Common\//, "", s); if (s=="" || s=="none" || s=="*") return ""; if (s~/^\[/) { p=s; sub(/^\[/, "", p); sub(/\].*$/, "", p) } else if (s~/^[0-9][0-9.]*%[0-9]+:/ || s~/^[0-9][0-9.]*:/) { n=split(s,a,":"); p=a[1] } else if (s~/^[0-9][0-9.]*%[0-9]+$/ || s~/^[0-9][0-9.]*$/) p=s; else if (s~/:/ && s~/[.][^.:]+$/) { p=s; sub(/[.][^.:]+$/, "", p) } else p=s; sub(/%[0-9]+$/, "", p); if (p=="0.0.0.0" || p=="::" || p=="*") return ""; return p }
function append(list,value) { if (value=="") return list; if (list=="") return value; return list "," value }
function add_profile(vip,type,profile,k,p,cert) { k=vip SUBSEP type SUBSEP profile; if (!profile_seen[k]) { profile_seen[k]=1; if (type=="clientssl") client_profiles[vip]=append(client_profiles[vip],profile); else server_profiles[vip]=append(server_profiles[vip],profile) } for (p in profile_certs) { split(p,pf,SUBSEP); if (pf[1]==type && pf[2]==profile) { cert=pf[3]; k=vip SUBSEP type SUBSEP cert; if (!cert_seen[k]) { cert_seen[k]=1; if (type=="clientssl") client_certs[vip]=append(client_certs[vip],cert); else server_certs[vip]=append(server_certs[vip],cert) } } } }
FILENAME==profilefile { profile_type[$1 SUBSEP $2]=1; profile_certs[$1 SUBSEP $2 SUBSEP $3]=1; next }
FILENAME==dnsfile { dns[$1]=$2; next }
FILENAME==statsfile { vips[$1]=1; raw_dest[$1]=$2; bitsin[$1]=$3; bitsout[$1]=$4; cur[$1]=$5; max[$1]=$6; tot[$1]=$7; avail[$1]=$8; enabled[$1]=$9; reason[$1]=$10; extra[$1]=$11; next }
FILENAME==poolbasefile { pool_monitor[$1]=$2; next }
FILENAME==poolmembersfile { pool=$1; ip=$2; port=$3; state=$4; key=pool SUBSEP ip SUBSEP port; if (!member_seen[key]) { member_seen[key]=1; resolved="NR"; if (ip in dns) resolved=dns[ip]; member_count[pool]++; if (member_count[pool]==1) { pool_ips[pool]=ip; pool_ports[pool]=port; pool_states[pool]=state; pool_resolved[pool]=resolved } else { pool_ips[pool]=pool_ips[pool] "," ip; pool_ports[pool]=pool_ports[pool] "," port; pool_states[pool]=pool_states[pool] "," state; pool_resolved[pool]=pool_resolved[pool] "," resolved } } next }
FILENAME==reffile { vip=$1; context=$2; profile=$3; vips[vip]=1; if ((context=="clientside" || context=="all") && (("clientssl" SUBSEP profile) in profile_type)) add_profile(vip,"clientssl",profile); if ((context=="serverside" || context=="all") && (("serverssl" SUBSEP profile) in profile_type)) add_profile(vip,"serverssl",profile); next }
FILENAME==rulesfile { vip=$1; rule=$2; vips[vip]=1; key=vip SUBSEP rule; if (!rule_seen[key]) { rule_seen[key]=1; rules[vip]=append(rules[vip],rule) } next }
FILENAME==basefile { vips[$1]=1; configured[$1]=$2; vip_pool[$1]=$3; next }
END { for (vip in vips) { dest=raw_dest[vip]; lookup_dest=dest; if (lookup_dest=="") lookup_dest=configured[vip]; ip=destination_ip(lookup_dest); resolved=""; if (ip!="") { if (ip in dns) resolved=dns[ip]; else resolved="NR" } pool=vip_pool[vip]; print vip,configured[vip],dest,resolved,avail[vip],enabled[vip],reason[vip],extra[vip],bitsin[vip],bitsout[vip],cur[vip],max[vip],tot[vip],pool,pool_monitor[pool],pool_ips[pool],pool_ports[pool],pool_states[pool],pool_resolved[pool],client_profiles[vip],server_profiles[vip],client_certs[vip],server_certs[vip],rules[vip] } }
AWK

###############################################################################
# Output headers
###############################################################################

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    'export_date' 'host' 'cert_name' 'used_by_profile' 'profile_used_by' \
    'expiration_date' 'security_type' 'serial_number' 'CU_username' \
    'Organization' 'CN' 'Issuer_CN' 'subject_alternative_name' \
    'vip_destination' 'vip_destination_resolved' 'clientside_bits_in' \
    'clientside_bits_out' 'clientside_cur_conns' 'clientside_max_conns' \
    'clientside_tot_conns' 'availability_state' 'enabled_state' \
    'status_reason' 'status_extra' > "$OUT_FILE" || exit 1

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    'export_date' 'host' 'vip_name' 'configured_destination' 'destination' \
    'destination_resolved' 'availability_state' 'enabled_state' \
    'status_reason' 'status_extra' 'clientside_bits_in' 'clientside_bits_out' \
    'clientside_cur_conns' 'clientside_max_conns' 'clientside_tot_conns' \
    'pool_name' 'pool_monitor' 'pool_member_ips' 'pool_member_ports' \
    'pool_member_admin_states' 'pool_member_resolved' 'client_ssl_profiles' \
    'server_ssl_profiles' 'client_certificates' 'server_certificates' \
    'irules' > "$VIP_OUT_FILE" || exit 1

###############################################################################
# SSH execution and signal-aware command control
###############################################################################

run_tmsh()
{
    typeset host="$1"
    typeset tmsh_command="$2"
    typeset output="$3"
    typeset rc

    CURRENT_HOST="$host"
    CURRENT_COMMAND="$tmsh_command"
    CURRENT_COMMAND_INTERRUPTED=0
    LAST_FAILED_OUTPUT=""

    echo "[$host] Running tmsh: $tmsh_command" >&2

    if [ "$HAVE_SETSID" -eq 1 ]; then
        setsid sshpass -e ssh $SSH_OPTS "${SSH_USER}@${host}" "$tmsh_command" < "$YES_FILE" > "$output" 2>&1 &
        CURRENT_SSH_GROUP=1
    else
        sshpass -e ssh $SSH_OPTS "${SSH_USER}@${host}" "$tmsh_command" < "$YES_FILE" > "$output" 2>&1 &
        CURRENT_SSH_GROUP=0
    fi

    CURRENT_SSH_PID=$!
    wait "$CURRENT_SSH_PID"
    rc=$?
    CURRENT_SSH_PID=""
    CURRENT_SSH_GROUP=0

    if [ "$CURRENT_COMMAND_INTERRUPTED" -eq 1 ]; then
        return 130
    fi

    if [ $rc -ne 0 ]; then
        LAST_FAILED_OUTPUT="$output"
        return 1
    fi

    if grep 'Syntax Error:' "$output" >/dev/null 2>&1; then
        LAST_FAILED_OUTPUT="$output"
        return 1
    fi

    if grep 'unexpected argument' "$output" >/dev/null 2>&1; then
        LAST_FAILED_OUTPUT="$output"
        return 1
    fi

    return 0
}

run_host_command()
{
    typeset host="$1"
    typeset command="$2"
    typeset output="$3"
    typeset rc

    [ "$HOST_FAILED" -eq 0 ] && [ "$HOST_INTERRUPTED" -eq 0 ] || return 1

    run_tmsh "$host" "$command" "$output"
    rc=$?

    if [ $rc -eq 130 ]; then
        HOST_INTERRUPTED=1
        return 1
    fi

    if [ $rc -ne 0 ]; then
        HOST_FAILED=1
        return 1
    fi

    return 0
}

###############################################################################
# Persistent DNS cache
###############################################################################

lookup_dns()
{
    typeset ip="$1"
    typeset cached
    typeset answer

    DNS_RESULT=""

    cached=$(awk -F '\t' -v ip="$ip" '$1==ip { value=$2 } END { if (value!="") print value }' "$DNS_CACHE_FILE")

    if [ -n "$cached" ]; then
        DNS_RESULT="$cached"
        return 0
    fi

    if [ "$DNS_LOOKUP_COUNT" -gt 0 ] && [ "$DNS_DELAY" != "0" ] && [ "$DNS_DELAY" != "0.0" ]; then
        sleep "$DNS_DELAY"
    fi

    DNS_LOOKUP_COUNT=$((DNS_LOOKUP_COUNT + 1))

    answer=$(nslookup "$ip" 2>/dev/null | awk '
        /name = / { value=$0; sub(/^.*name = /, "", value); sub(/[.]$/, "", value); print value; exit }
        /^[[:space:]]*Name:[[:space:]]*/ { value=$0; sub(/^[[:space:]]*Name:[[:space:]]*/, "", value); sub(/[.]$/, "", value); if (value!="") { print value; exit } }
    ')

    [ -n "$answer" ] || answer="NR"

    printf '%s\t%s\n' "$ip" "$answer" >> "$DNS_CACHE_FILE"
    DNS_RESULT="$answer"
    return 0
}

resolve_dns_file()
{
    typeset input="$1"
    typeset output="$2"
    typeset ip

    : > "$output" || return 1

    while IFS= read -r ip || [ -n "$ip" ]
    do
        ip=$(printf '%s' "$ip" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ -n "$ip" ] || continue
        lookup_dns "$ip"
        printf '%s\t%s\n' "$ip" "$DNS_RESULT" >> "$output" || return 1
    done < "$input"

    return 0
}

###############################################################################
# Main processing loop
###############################################################################

total_cert_rows=0
total_vip_rows=0
failed_hosts=0
interrupted_hosts=0

while IFS= read -r host || [ -n "$host" ]
do
    host=$(printf '%s' "$host" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    case "$host" in
        ''|'#'*)
            continue
            ;;
    esac

    echo "Processing $host ..." >&2

    hostdir="$TMPROOT/$(printf '%s' "$host" | tr '/:' '__')"

    mkdir -p "$hostdir" || {
        echo "ERROR: $host: cannot create temporary directory" >&2
        failed_hosts=$((failed_hosts + 1))
        continue
    }

    HOST_FAILED=0
    HOST_INTERRUPTED=0
    LAST_FAILED_OUTPUT=""

    run_host_command "$host" 'cd /Common; list sys file ssl-cert all-properties' "$hostdir/certs.raw"
    run_host_command "$host" 'cd /Common; list sys file ssl-key all-properties' "$hostdir/keys.raw"
    run_host_command "$host" 'cd /Common; list ltm profile client-ssl all-properties' "$hostdir/clientssl.raw"
    run_host_command "$host" 'cd /Common; list ltm profile server-ssl all-properties' "$hostdir/serverssl.raw"
    run_host_command "$host" 'cd /Common; list ltm virtual { profiles pool destination rules }' "$hostdir/virtual_config.raw"
    run_host_command "$host" 'cd /Common; show ltm virtual raw field-fmt' "$hostdir/virtual_stats.raw"
    run_host_command "$host" 'cd /Common; list ltm monitor https all-properties' "$hostdir/monitors.raw"
    run_host_command "$host" 'cd /Common; list ltm pool' "$hostdir/pools.raw"

    if [ "$HOST_INTERRUPTED" -eq 1 ]; then
        echo "[$host] Host skipped because the current SSH command was interrupted with Ctrl+C." >&2
        interrupted_hosts=$((interrupted_hosts + 1))
        continue
    fi

    if [ "$HOST_FAILED" -ne 0 ]; then
        echo "ERROR: $host: SSH or remote tmsh command failed" >&2
        if [ -n "$LAST_FAILED_OUTPUT" ] && [ -s "$LAST_FAILED_OUTPUT" ]; then
            echo "--- Captured command output ---" >&2
            cat "$LAST_FAILED_OUTPUT" >&2
        fi
        failed_hosts=$((failed_hosts + 1))
        continue
    fi

    now=$(date +%s) || {
        echo "ERROR: $host: cannot determine local epoch time" >&2
        failed_hosts=$((failed_hosts + 1))
        continue
    }

    cutoff=$((now + MIN_DAYS * 86400))
    LOCAL_FAILED=0

    awk -v cutoff="$cutoff" -f "$TMPROOT/parse_certs.awk" "$hostdir/certs.raw" > "$hostdir/certs.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/certs.unsorted.tsv" > "$hostdir/certs.tsv" || LOCAL_FAILED=1

    [ "$LOCAL_FAILED" -eq 0 ] && awk -f "$TMPROOT/parse_keys.awk" "$hostdir/keys.raw" > "$hostdir/keys.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/keys.unsorted.tsv" > "$hostdir/keys.tsv" || LOCAL_FAILED=1

    [ "$LOCAL_FAILED" -eq 0 ] && awk -v ptype=clientssl -f "$TMPROOT/parse_profiles.awk" "$hostdir/clientssl.raw" > "$hostdir/client_profiles.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && awk -v ptype=serverssl -f "$TMPROOT/parse_profiles.awk" "$hostdir/serverssl.raw" > "$hostdir/server_profiles.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && cat "$hostdir/client_profiles.tsv" "$hostdir/server_profiles.tsv" > "$hostdir/profiles.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/profiles.unsorted.tsv" > "$hostdir/profiles.tsv" || LOCAL_FAILED=1

    [ "$LOCAL_FAILED" -eq 0 ] && awk -v mode=base -f "$TMPROOT/parse_virtual_config.awk" "$hostdir/virtual_config.raw" > "$hostdir/virtual_base.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && awk -v mode=profiles -f "$TMPROOT/parse_virtual_config.awk" "$hostdir/virtual_config.raw" > "$hostdir/virtual_refs.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/virtual_refs.unsorted.tsv" > "$hostdir/virtual_refs.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && awk -v mode=rules -f "$TMPROOT/parse_virtual_config.awk" "$hostdir/virtual_config.raw" > "$hostdir/virtual_rules.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/virtual_rules.unsorted.tsv" > "$hostdir/virtual_rules.tsv" || LOCAL_FAILED=1

    [ "$LOCAL_FAILED" -eq 0 ] && awk -f "$TMPROOT/parse_virtual_stats.awk" "$hostdir/virtual_stats.raw" > "$hostdir/virtual_stats.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/virtual_stats.unsorted.tsv" > "$hostdir/virtual_stats.tsv" || LOCAL_FAILED=1

    [ "$LOCAL_FAILED" -eq 0 ] && awk -f "$TMPROOT/parse_monitors.awk" "$hostdir/monitors.raw" > "$hostdir/monitors.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/monitors.unsorted.tsv" > "$hostdir/monitors.tsv" || LOCAL_FAILED=1

    [ "$LOCAL_FAILED" -eq 0 ] && awk -v mode=base -f "$TMPROOT/parse_pools.awk" "$hostdir/pools.raw" > "$hostdir/pool_base.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/pool_base.unsorted.tsv" > "$hostdir/pool_base.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && awk -v mode=members -f "$TMPROOT/parse_pools.awk" "$hostdir/pools.raw" > "$hostdir/pool_members.tsv" || LOCAL_FAILED=1

    if [ "$LOCAL_FAILED" -ne 0 ]; then
        echo "ERROR: $host: local parsing failed" >&2
        failed_hosts=$((failed_hosts + 1))
        continue
    fi

    awk -v statsfile="$hostdir/virtual_stats.tsv" -v basefile="$hostdir/virtual_base.tsv" -v membersfile="$hostdir/pool_members.tsv" -f "$TMPROOT/collect_dns_ips.awk" "$hostdir/virtual_stats.tsv" "$hostdir/virtual_base.tsv" "$hostdir/pool_members.tsv" > "$hostdir/dns_ips.unsorted" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/dns_ips.unsorted" > "$hostdir/dns_ips" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && resolve_dns_file "$hostdir/dns_ips" "$hostdir/dns.tsv" || LOCAL_FAILED=1

    if [ "$LOCAL_FAILED" -ne 0 ]; then
        echo "ERROR: $host: local DNS processing failed" >&2
        failed_hosts=$((failed_hosts + 1))
        continue
    fi

    awk -v certfile="$hostdir/certs.tsv" -v keyfile="$hostdir/keys.tsv" -v profilefile="$hostdir/profiles.tsv" -v basefile="$hostdir/virtual_base.tsv" -v reffile="$hostdir/virtual_refs.tsv" -v monitorfile="$hostdir/monitors.tsv" -v statsfile="$hostdir/virtual_stats.tsv" -v dnsfile="$hostdir/dns.tsv" -f "$TMPROOT/join_cert_report.awk" "$hostdir/certs.tsv" "$hostdir/keys.tsv" "$hostdir/profiles.tsv" "$hostdir/virtual_base.tsv" "$hostdir/virtual_refs.tsv" "$hostdir/monitors.tsv" "$hostdir/virtual_stats.tsv" "$hostdir/dns.tsv" > "$hostdir/cert_result.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/cert_result.unsorted.tsv" > "$hostdir/cert_result.tsv" || LOCAL_FAILED=1

    awk -v profilefile="$hostdir/profiles.tsv" -v dnsfile="$hostdir/dns.tsv" -v statsfile="$hostdir/virtual_stats.tsv" -v poolbasefile="$hostdir/pool_base.tsv" -v poolmembersfile="$hostdir/pool_members.tsv" -v reffile="$hostdir/virtual_refs.tsv" -v rulesfile="$hostdir/virtual_rules.tsv" -v basefile="$hostdir/virtual_base.tsv" -f "$TMPROOT/join_flat_report.awk" "$hostdir/profiles.tsv" "$hostdir/dns.tsv" "$hostdir/virtual_stats.tsv" "$hostdir/pool_base.tsv" "$hostdir/pool_members.tsv" "$hostdir/virtual_refs.tsv" "$hostdir/virtual_rules.tsv" "$hostdir/virtual_base.tsv" > "$hostdir/vip_result.unsorted.tsv" || LOCAL_FAILED=1
    [ "$LOCAL_FAILED" -eq 0 ] && LC_ALL=C sort -u "$hostdir/vip_result.unsorted.tsv" > "$hostdir/vip_result.tsv" || LOCAL_FAILED=1

    if [ "$LOCAL_FAILED" -ne 0 ]; then
        echo "ERROR: $host: local correlation failed" >&2
        failed_hosts=$((failed_hosts + 1))
        continue
    fi

    cert_rows=$(awk 'END { print NR+0 }' "$hostdir/cert_result.tsv")
    vip_rows=$(awk 'END { print NR+0 }' "$hostdir/vip_result.tsv")

    if [ "$cert_rows" -gt 0 ]; then
        awk -v export_date="$EXPORT_DATE" -v host="$host" 'BEGIN { FS=OFS="\t" } { print export_date,host,$0 }' "$hostdir/cert_result.tsv" >> "$OUT_FILE" || {
            echo "ERROR: $host: cannot append certificate report" >&2
            failed_hosts=$((failed_hosts + 1))
            continue
        }
        total_cert_rows=$((total_cert_rows + cert_rows))
        echo "[$host] Exported $cert_rows certificate usage row(s)." >&2
    else
        echo "[$host] No matching certificate records found." >&2
    fi

    if [ "$vip_rows" -gt 0 ]; then
        awk -v export_date="$EXPORT_DATE" -v host="$host" 'BEGIN { FS=OFS="\t" } { print export_date,host,$0 }' "$hostdir/vip_result.tsv" >> "$VIP_OUT_FILE" || {
            echo "ERROR: $host: cannot append virtual mapping report" >&2
            failed_hosts=$((failed_hosts + 1))
            continue
        }
        total_vip_rows=$((total_vip_rows + vip_rows))
        echo "[$host] Exported $vip_rows virtual mapping row(s)." >&2
    else
        echo "[$host] No virtual servers found." >&2
    fi

done < "$HOSTS_FILE"

echo "Completed certificate report: $total_cert_rows row(s) written to $OUT_FILE." >&2
echo "Completed virtual report: $total_vip_rows row(s) written to $VIP_OUT_FILE." >&2
echo "Hosts failed: $failed_hosts; hosts interrupted with Ctrl+C: $interrupted_hosts." >&2
echo "Persistent DNS cache: $DNS_CACHE_FILE" >&2
