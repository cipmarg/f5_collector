#!/bin/ksh

HOSTS_FILE="hosts.inv"

[ -n "$SSHPASS" ] || {
    echo "ERROR: export SSHPASS='password'" >&2
    exit 1
}

host=$(awk 'NF && $1 !~ /^#/ {
    gsub(/\r/, "")
    print $1
    exit
}' "$HOSTS_FILE")

[ -n "$host" ] || {
    echo "ERROR: no host found in $HOSTS_FILE" >&2
    exit 1
}

SSH_OPTS="-o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null \
-o LogLevel=ERROR \
-o ConnectTimeout=15 \
-o PreferredAuthentications=keyboard-interactive,password \
-o KbdInteractiveAuthentication=yes \
-o PubkeyAuthentication=no \
-o NumberOfPasswordPrompts=1"

TMPDIR=$(mktemp -d /tmp/f5certtest.XXXXXX) || exit 1
trap 'rm -rf "$TMPDIR"' EXIT HUP INT TERM

run_tmsh()
{
    printf 'y\n' |
        sshpass -e ssh $SSH_OPTS -T "${USER}@${host}" "$1"
}

capture()
{
    file="$1"
    command="$2"

    echo "Running: $command" >&2

    run_tmsh "$command" > "$file" 2>&1
    rc=$?

    if [ $rc -ne 0 ] || grep -q "Syntax Error:" "$file"; then
        echo "ERROR running command:" >&2
        cat "$file" >&2
        exit 1
    fi
}

echo "Testing host: $host"
echo "SSH user:    $USER"

capture "$TMPDIR/certs" \
    "cd /Common; list sys file ssl-cert all-properties"

capture "$TMPDIR/keys" \
    "cd /Common; list sys file ssl-key all-properties"

capture "$TMPDIR/clientssl" \
    "cd /Common; list ltm profile client-ssl"

capture "$TMPDIR/serverssl" \
    "cd /Common; list ltm profile server-ssl"

capture "$TMPDIR/virtuals" \
    "cd /Common; list ltm virtual profiles"

capture "$TMPDIR/monitors" \
    "cd /Common; list ltm monitor https"

echo
echo "=== Object counts ==="
printf "Certificates:       "
grep -c '^sys file ssl-cert ' "$TMPDIR/certs"

printf "Private keys:       "
grep -c '^sys file ssl-key ' "$TMPDIR/keys"

printf "Client SSL profiles:"
grep -c '^ltm profile client-ssl ' "$TMPDIR/clientssl"

printf "Server SSL profiles:"
grep -c '^ltm profile server-ssl ' "$TMPDIR/serverssl"

printf "Virtual servers:    "
grep -c '^ltm virtual ' "$TMPDIR/virtuals"

printf "HTTPS monitors:     "
grep -c '^ltm monitor https ' "$TMPDIR/monitors"

echo
echo "=== Sample certificate metadata ==="

awk '
function dnvalue(dn, key, n, a, i, p) {
    n = split(dn, a, ",")
    for (i = 1; i <= n; i++) {
        p = index(a[i], "=")
        if (p && substr(a[i], 1, p - 1) == key)
            return substr(a[i], p + 1)
    }
    return ""
}

/^sys file ssl-cert / {
    name = $4
    expiration = cn = org = issuer_cn = ""
    active = 1
    next
}

active && /^[ \t]+expiration-string / {
    expiration = $0
    sub(/^[^"]*"/, "", expiration)
    sub(/"[ \t]*$/, "", expiration)
}

active && /^[ \t]+subject "/ {
    subject = $0
    sub(/^[^"]*"/, "", subject)
    sub(/"[ \t]*$/, "", subject)
    cn = dnvalue(subject, "CN")
    org = dnvalue(subject, "O")
}

active && /^[ \t]+issuer "/ {
    issuer = $0
    sub(/^[^"]*"/, "", issuer)
    sub(/"[ \t]*$/, "", issuer)
    issuer_cn = dnvalue(issuer, "CN")
}

active && /^}/ {
    print name "|" expiration "|" org "|" cn "|" issuer_cn
    count++
    active = 0
    if (count == 3)
        exit
}
' "$TMPDIR/certs"

echo
echo "=== Sample key security types ==="

awk '
/^sys file ssl-key / {
    key = $4
}

/^[ \t]+security-type / {
    print key "|" $2
    count++
    if (count == 5)
        exit
}
' "$TMPDIR/keys"

echo
echo "=== Sample profile certificate/key references ==="

cat "$TMPDIR/clientssl" "$TMPDIR/serverssl" |
awk '
/^ltm profile (client|server)-ssl / {
    type = $3
    profile = $4
    cert = key = ""
    active = 1
    next
}

active && /^[ \t]+cert / && $2 != "none" && cert == "" {
    cert = $2
}

active && /^[ \t]+key / && $2 != "none" && key == "" {
    key = $2
}

active && /^}/ {
    if (cert != "" || key != "") {
        print type "|" profile "|" cert "|" key
        count++
    }

    active = 0

    if (count == 5)
        exit
}
'

echo
echo "=== Sample VIP profile references ==="

awk '
/^ltm virtual / {
    vip = $3
    active = 1
    next
}

active && /^[ \t]+[^ \t]+[ \t]+\{$/ {
    candidate = $1
}

active && /^[ \t]+context[ \t]+(clientside|serverside)/ {
    print candidate "|VIP_" vip "|" $2
    count++
    if (count == 5)
        exit
}

active && /^}/ {
    active = 0
}
' "$TMPDIR/virtuals"

echo
echo "=== Sample HTTPS-monitor profile references ==="

awk '
/^ltm monitor https / {
    monitor = $4
}

/^[ \t]+ssl-profile / && $2 != "none" {
    print $2 "|HTTPS_MON_" monitor
    count++
    if (count == 5)
        exit
}
' "$TMPDIR/monitors"

echo
echo "Test completed successfully."
