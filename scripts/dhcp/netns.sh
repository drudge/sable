#!/usr/bin/env bash
# DHCP end to end: the real sable binary on port 67 in a network namespace,
# holding only CAP_NET_BIND_SERVICE, with busybox udhcpc clients, a squatter
# and a second DHCP server (dnsmasq) on a bridge. Nothing leaves the
# namespaces. Needs sudo, busybox and dnsmasq; runs only with
# SABLE_TEST_NETNS=1. Usage: SABLE_TEST_NETNS=1 scripts/dhcp/netns.sh [worktree]
set -u
if [ "${SABLE_TEST_NETNS:-}" != 1 ]; then echo "skipped: set SABLE_TEST_NETNS=1 to run the DHCP namespace harness"; exit 0; fi
for tool in busybox /usr/sbin/dnsmasq python3 setpriv; do
  command -v "$tool" >/dev/null || { echo "missing $tool: install busybox and dnsmasq-base"; exit 2; }
done
src=$(cd "${1:-.}" && pwd); here=$(cd "$(dirname "$0")" && pwd)
export PATH=/usr/local/go/bin:$PATH GOEXPERIMENT=jsonv2 GOFLAGS=-p=1
work=$(mktemp -d /tmp/sable-e2e.XXXXXX); chmod 755 "$work"
S=sdh-s; pid=; NETNS="$S sdh-c1 sdh-c2 sdh-c3 sdh-q sdh-r"
stop_server() { [ -n "$pid" ] && sudo kill "$pid" 2>/dev/null; for _ in $(seq 300); do sudo kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done; pid=; }
cleanup() { stop_server; [ -n "${hold:-}" ] && sudo kill "$hold" 2>/dev/null; sudo pkill -f "udhcpc -i sdh" 2>/dev/null; [ -f "$work/rogue.pid" ] && sudo kill "$(cat "$work/rogue.pid")" 2>/dev/null; for n in $NETNS; do sudo ip netns del $n 2>/dev/null; done; [ "${KEEP:-}" ] || rm -rf "$work"; }
trap cleanup EXIT; for n in $NETNS; do sudo ip netns del $n 2>/dev/null; done
(cd "$src" && go build -o "$work/sable" ./cmd/sable) || { echo "build failed"; exit 2; }
echo "sable built from $(git -C "$src" rev-parse --short=8 HEAD)"
for n in $NETNS; do sudo ip netns add $n && sudo ip -n $n link set lo up; done
sudo ip -n $S link add br0 type bridge && sudo ip -n $S link set br0 up && sudo ip -n $S addr add 192.0.2.1/24 dev br0
for c in c1 c2 c3 q r; do
  sudo ip -n $S link add v$c type veth peer name sdh$c netns sdh-$c && sudo ip -n $S link set v$c master br0 &&
    sudo ip -n $S link set v$c up && sudo ip -n sdh-$c link set sdh$c up || { echo "netns setup failed"; exit 2; }
done
sudo ip netns exec $S sysctl -qw net.ipv4.ping_group_range="0 2147483647"
# A default route to nowhere: without one, main's DNSSEC trust-anchor refresh
# retries "network is unreachable" about 7,700 times a second and fills the log.
sudo ip -n $S route add default via 192.0.2.254
sed -e 's/^http_listen = .*/http_listen = "127.0.0.1:15380"/' -e 's/^dns_listen = .*/dns_listen = ["127.0.0.1:18053"]/' \
    -e 's/^domains = \["example.invalid"\]/domains = []/' \
    -e 's/^dnssec_trust_anchor_updates = .*/dnssec_trust_anchor_updates = false/' "$src/config.example.toml" > "$work/sable.toml"
cat >> "$work/sable.toml" <<'TOML'

[dhcp]
enabled = true

[[dhcp.scopes]]
id = "lan"
name = "LAN"
subnet = "192.0.2.0/24"
router = "192.0.2.1"
lease = "1h"

[[dhcp.scopes.ranges]]
start = "192.0.2.100"
end = "192.0.2.119"
TOML
mkdir -p "$work/data"; cd "$work"
cat > hook.sh <<'H'
#!/bin/sh
case "$1" in
  deconfig) ip addr flush dev "$interface";;
  bound|renew) ip addr replace "$ip/24" dev "$interface"; echo "CLIENT $interface $1 ip=$ip lease=$lease server=$serverid router=$router";;
esac
exit 0
H
chmod +x hook.sh
start_server() {
  sudo ip netns exec $S setpriv --reuid "$(id -u)" --regid "$(id -g)" --init-groups \
    --inh-caps +net_bind_service --ambient-caps +net_bind_service --bounding-set -all,+net_bind_service \
    "$work/sable" serve --config "$work/sable.toml" >> "$work/log" 2>&1 &
  for _ in $(seq 100); do pid=$(pgrep -n -f "^$work/sable serve"); [ -n "$pid" ] && grep -q "DHCP server started" log && break; sleep 0.1; done
  [ -n "$pid" ] || { echo "server didn't start"; tail -20 log; exit 2; }
}
lease() { sudo ip netns exec sdh-$1 busybox udhcpc -i sdh$1 -f -n -q -t 5 -T 2 -s "$work/hook.sh" "${@:2}" 2>&1 | grep CLIENT; }
ip_of() { sed -n 's/.* ip=\([0-9.]*\) .*/\1/p' <<<"$1"; }
rows() { python3 - "$work" <<'PY'
import glob, sqlite3, sys
for db in glob.glob(sys.argv[1] + "/**/*.db", recursive=True) + glob.glob(sys.argv[1] + "/**/*.sqlite*", recursive=True):
    try:
        c = sqlite3.connect("file:" + db + "?mode=ro", uri=True)
        for r in c.execute("SELECT address, mac, state, client_key FROM sable_dhcp_leases ORDER BY address"):
            print("ROW", *r)
    except sqlite3.Error:
        pass
PY
}
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
check() { if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1: got '$2', want '$3'"; fi; }
started() { grep -c "DHCP server started" log; }

# A host DHCP client's socket on port 68, shaped like systemd-networkd's
# (address:68, bound to the device, SO_REUSEADDR): the probe shares port 68
# with it (D34), while port 67 is never shared (D33).
sudo ip netns exec $S python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"br0")
s.bind(("192.0.2.1", 68)); time.sleep(3600)' &
sleep 0.5; hold=$(pgrep -n -f 's.bind\(\("192.0.2.1", 68\)\)')
start_server
echo "server: pid $pid, uid $(sudo awk '/^Uid/{print $2}' /proc/$pid/status), CapEff $(sudo awk '/^CapEff/{print $2}' /proc/$pid/status)"
a=$(lease c1); echo "$a"; ip1=$(ip_of "$a")
case "$ip1" in 192.0.2.1[01][0-9]) ok "c1 leased $ip1 from the range";; *) bad "c1 got no lease in the range: '$a'";; esac
case "$a" in *"lease=3600 server=192.0.2.1 router=192.0.2.1"*) ok "c1 lease 3600 s, server and router 192.0.2.1";; *) bad "c1 options: $a";; esac
b=$(lease c2); echo "$b"; ip2=$(ip_of "$b")
[ -n "$ip2" ] && [ "$ip2" != "$ip1" ] && ok "c2 leased a different address ($ip2)" || bad "c2: '$b'"
a2=$(lease c1 -r "$ip1"); check "c1 asking again keeps its address" "$(ip_of "$a2")" "$ip1"
rows; check "store has both leases active" "$(rows | grep -c ' active ')" 2

echo "--- a change outside [dhcp] (one more forwarder)"
n=$(started)
sed -i 's/^forwarders = .*/forwarders = ["1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53"]/' sable.toml; sleep 3
grep -i "configuration" log | tail -2
check "DHCP server not restarted by it" "$(started)" "$n"
check "c1 still renews" "$(ip_of "$(lease c1 -r "$ip1")")" "$ip1"

echo "--- a change inside [dhcp] (lease 1h -> 2h)"
sed -i 's/^lease = "1h"/lease = "2h"/' sable.toml; sleep 3
check "DHCP server restarted once" "$(started)" "$((n + 1))"
b2=$(lease c2 -r "$ip2"); echo "$b2"
check "c2 keeps its address across the reload" "$(ip_of "$b2")" "$ip2"
case "$b2" in *"lease=7200 "*) ok "c2 now gets the 2h lease";; *) bad "c2 lease time after reload: $b2";; esac

echo "--- process restart"
t0=$(date +%s); stop_server; echo "server exited $(( $(date +%s) - t0 )) s after SIGTERM"; : > log; start_server
check "c1 keeps its address across a restart" "$(ip_of "$(lease c1)")" "$ip1"

echo "--- release"
sudo ip netns exec sdh-c2 busybox udhcpc -i sdhc2 -f -R -t 5 -T 2 -r "$ip2" -s "$work/hook.sh" > c2.out 2>&1 &
for _ in $(seq 60); do grep -q CLIENT c2.out && break; sleep 0.1; done
sudo pkill -TERM -f "udhcpc -i sdhc2"; sleep 1
rows | grep " $ip2 \|^ROW $ip2 "
check "c2's lease is released in the store" "$(rows | awk -v ip="$ip2" '$2==ip{print $4}')" released

echo "--- squatter on the bridge holds three free addresses and drops ping"
for last in 100 101 102 103 104; do q="192.0.2.$last"; [ "$q" != "$ip1" ] && [ "$q" != "$ip2" ] && sudo ip -n sdh-q addr add "$q/24" dev sdhq; done
sudo ip netns exec sdh-q sysctl -qw net.ipv4.icmp_echo_ignore_all=1
squat=$(sudo ip -n sdh-q -4 -o addr show dev sdhq | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' '); echo "squatted: $squat"
c=$(sudo ip netns exec sdh-c3 busybox udhcpc -i sdhc3 -f -n -q -t 8 -T 2 -s "$work/hook.sh" 2>&1 | grep CLIENT); echo "$c"; ip3=$(ip_of "$c")
if [ -z "$ip3" ]; then bad "c3 got no lease"; elif grep -qw "$ip3" <<<"$squat"; then bad "c3 was given squatted $ip3"; else ok "c3 leased $ip3, not a squatted address"; fi
rows | grep -v " active \| released " ; echo "conflict rows: $(rows | grep -c conflict)"

echo "--- 20,000 DISCOVERs from random hardware addresses"
rss() { sudo awk '/^VmRSS/{print $2}' /proc/$pid/status; }
r0=$(rss); sudo ip netns exec sdh-c2 python3 "$here/flood.py" sdhc2 20000; sleep 1; r1=$(rss)
echo "RSS before ${r0} kB, after ${r1} kB"
[ $((r1 - r0)) -lt 262144 ] && ok "RSS grew under 256 MB" || bad "RSS grew $((r1 - r0)) kB"
sudo kill -0 "$pid" 2>/dev/null && ok "server still running" || bad "server died"
check "c1 still renews after the flood" "$(ip_of "$(lease c1 -r "$ip1")")" "$ip1"
grep -ci "panic" log | sed 's/^/panics in log: /'
grep -i "dhcp" log | grep -vi "started" | cut -c1-220 | sort | uniq -c | sort -rn | head -8
echo "--- a second DHCP server (dnsmasq at 192.0.2.2) on the bridge"
sudo ip -n sdh-r addr add 192.0.2.2/24 dev sdhr
sudo ip netns exec sdh-r /usr/sbin/dnsmasq --port=0 --interface=sdhr --bind-interfaces --dhcp-range=192.0.2.200,192.0.2.210,1h \
  --dhcp-leasefile="$work/rogue.leases" --pid-file="$work/rogue.pid" --user="$(id -un)" --group="$(id -gn)" || bad "dnsmasq didn't start"
stop_server; : > log; start_server
for _ in $(seq 80); do grep -q "another DHCP server" log && break; sleep 0.1; done
grep "another DHCP server" log | cut -c1-240
grep "another DHCP server" log | grep -q "192.0.2.2" && ok "the probe reports dnsmasq at 192.0.2.2" || bad "no report of the second server"
grep "another DHCP server" log | grep -q "server=192.0.2.1 " && bad "the probe reported this server itself" || ok "the probe doesn't report this server"
grep -q "can't probe for another DHCP server" log && bad "the probe couldn't share port 68 with the host's DHCP client" || ok "the probe shares port 68 with the host's DHCP client"

[ "${KEEP:-}" ] && echo "kept $work"
exit $fail
