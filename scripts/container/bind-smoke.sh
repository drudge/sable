#!/usr/bin/env bash
# Checks that the container image binds DNS on a port below 1024 under host
# networking with only NET_BIND_SERVICE, and still starts on a bridge with
# every capability dropped. See docs/design/dhcp.md, "Docker bind check".
#
# Usage: scripts/container/bind-smoke.sh [image]
# Without an image it builds the native-architecture image from the working tree.
set -euo pipefail

address=127.0.0.77
image=${1:-}
work=$(mktemp -d)
containers=()
cleanup() {
	for name in "${containers[@]}"; do docker rm --force "$name" >/dev/null 2>&1 || true; done
	rm -rf "$work"
}
trap cleanup EXIT

build_image() {
	local platform="linux/$(go env GOARCH)"
	mkdir -p "$work/context/$platform"
	CGO_ENABLED=0 GOOS=linux GOEXPERIMENT=jsonv2 go build -trimpath -o "$work/context/$platform/sable" ./cmd/sable
	cp -R Dockerfile docker "$work/context/"
	image=sable-bind-smoke:local
	docker buildx build --quiet --load --platform "$platform" --tag "$image" "$work/context" >/dev/null
}

wait_healthy() {
	local url=$1 name=$2
	for _ in $(seq 60); do
		if curl --noproxy "*" --silent --fail --max-time 2 "$url" >/dev/null; then return 0; fi
		if [ "$(docker inspect --format '{{.State.Running}}' "$name")" != true ]; then break; fi
		sleep 0.5
	done
	echo "FAIL: $name never answered $url" >&2
	docker logs "$name" 2>&1 | tail -20 >&2
	return 1
}

# dns_answers sends version.bind CH TXT over TCP and checks the reply carries its ID.
dns_answers() {
	local reply
	reply=$(timeout 5 bash -c '
		exec 3<>"/dev/tcp/$1/53"
		printf "\x00\x1e\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03" >&3
		head -c 4 <&3 | od -An -tx1' _ "$address" 2>/dev/null | tr -d ' \n')
	[ "${reply:4:4}" = abcd ]
}

host_network() {
	local name="sable-bind-host-$$"
	mkdir -p "$work/config"
	sed -e "s|^http_listen = .*|http_listen = \"$address:5380\"|" \
		-e "s|^dns_listen = .*|dns_listen = [\"$address:53\"]|" docker/data/sable.toml >"$work/config/sable.toml"
	chmod -R a+rX "$work/config"
	containers+=("$name")
	docker run --detach --name "$name" --network host --cap-drop ALL --cap-add NET_BIND_SERVICE \
		--volume "$work/config:/config:ro" "$image" serve --config /config/sable.toml >/dev/null
	wait_healthy "http://$address:5380/api/v1/health" "$name"
	if ! dns_answers; then
		echo "FAIL: host network: no DNS answer on $address:53" >&2
		docker logs "$name" 2>&1 | tail -20 >&2
		return 1
	fi
	local status
	status=$(cat "/proc/$(docker inspect --format '{{.State.Pid}}' "$name")/status")
	if ! grep -qx $'CapEff:\t0000000000000400' <<<"$status" || ! grep -qx $'CapAmb:\t0000000000000400' <<<"$status"; then
		echo "FAIL: host network: want CAP_NET_BIND_SERVICE alone, effective and ambient" >&2
		grep ^Cap <<<"$status" >&2
		return 1
	fi
	echo "ok: host network, NET_BIND_SERVICE only: DNS answers on $address:53, CapEff=CapAmb=0x400"
}

bridge_no_capabilities() {
	local name="sable-bind-bridge-$$" port
	containers+=("$name")
	docker run --detach --name "$name" --cap-drop ALL --publish 127.0.0.1::5380/tcp "$image" >/dev/null
	port=$(docker port "$name" 5380/tcp | head -1 | sed 's/.*://')
	wait_healthy "http://127.0.0.1:$port/api/v1/health" "$name"
	echo "ok: bridge, every capability dropped: starts"
}

if [ -z "$image" ]; then build_image; fi
host_network
bridge_no_capabilities
