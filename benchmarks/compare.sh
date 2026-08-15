#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_DIRECTORY=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/.." && pwd)

MODE=${MODE:-managed}
QUERY_FILE=${QUERY_FILE:-"$SCRIPT_DIRECTORY/queries.txt"}
DURATION=${DURATION:-60}
WARMUP=${WARMUP:-15}
CLIENTS=${CLIENTS:-8}
THREADS=${THREADS:-4}
OUTSTANDING=${OUTSTANDING:-1000}
WARMUP_OUTSTANDING=${WARMUP_OUTSTANDING:-1}
TIMEOUT=${TIMEOUT:-2}
RUNS=${RUNS:-5}
MAX_LOSS_PERCENT=${MAX_LOSS_PERCENT:-1}
TRANSPORT=${TRANSPORT:-udp}
DNSSEC_OK=${DNSSEC_OK:-true}
UPSTREAM=${UPSTREAM:-1.1.1.1:53}
CACHE_SIZE=${CACHE_SIZE:-10000}
CPU_LIMIT=${CPU_LIMIT:-2}
MEMORY_LIMIT=${MEMORY_LIMIT:-1g}
SABLE_HOST=${SABLE_HOST:-127.0.0.1}
SABLE_PORT=${SABLE_PORT:-18053}
SABLE_HTTP_PORT=${SABLE_HTTP_PORT:-15380}
TECHNITIUM_HOST=${TECHNITIUM_HOST:-127.0.0.1}
TECHNITIUM_PORT=${TECHNITIUM_PORT:-18054}
TECHNITIUM_HTTP_PORT=${TECHNITIUM_HTTP_PORT:-15381}
TECHNITIUM_IMAGE=${TECHNITIUM_IMAGE:-technitium/dns-server:15.4.0}
PULL_TECHNITIUM=${PULL_TECHNITIUM:-if-missing}
READY_TIMEOUT=${READY_TIMEOUT:-60}
AUTO_START_DOCKER=${AUTO_START_DOCKER:-true}
DOCKER_START_TIMEOUT=${DOCKER_START_TIMEOUT:-120}
PLAN_ONLY=${PLAN_ONLY:-false}
SUMMARY_ONLY=${SUMMARY_ONLY:-false}
RESOURCE_SAMPLE_INTERVAL=${RESOURCE_SAMPLE_INTERVAL:-1}

RUN_IDENTIFIER=${RUN_IDENTIFIER:-"$(date -u +%Y%m%dT%H%M%SZ)-$$"}
CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RESULTS_DIRECTORY=${RESULTS_DIRECTORY:-"$REPOSITORY_DIRECTORY/_work/benchmarks/$RUN_IDENTIFIER"}
case "$RESULTS_DIRECTORY" in
	/*) ;;
	*) RESULTS_DIRECTORY="$REPOSITORY_DIRECTORY/$RESULTS_DIRECTORY" ;;
esac
SUMMARY_FILE="$RESULTS_DIRECTORY/summary.tsv"
AGGREGATE_FILE="$RESULTS_DIRECTORY/aggregate.tsv"
RESOURCES_FILE="$RESULTS_DIRECTORY/resources.tsv"
WARMUP_SUMMARY_FILE="$RESULTS_DIRECTORY/warmup-summary.tsv"
MANIFEST_FILE="$RESULTS_DIRECTORY/manifest.toml"
SABLE_IMAGE="sable-benchmark:$RUN_IDENTIFIER"
SABLE_CONTAINER=""
TECHNITIUM_CONTAINER=""
SABLE_IMAGE_ID=""
SABLE_BINARY_SHA256=""
TECHNITIUM_IMAGE_ID=""
TECHNITIUM_IMAGE_DIGEST=""
TECHNITIUM_SETTINGS_API_VERIFIED=false
RESOURCE_SAMPLER_PID=""
RESOURCE_SAMPLER_FILE=""
RESOURCE_SAMPLER_STOP_FILE=""
DOCKER_AUTO_STARTED=false
COMPLETED=false

fail() {
	printf 'benchmarkCompare: %s\n' "$*" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "$1 is required$2"
}

is_positive_integer() {
	case $1 in
		''|*[!0-9]*) return 1 ;;
		*) [ "$1" -gt 0 ] ;;
	esac
}

is_port() {
	is_positive_integer "$1" && [ "$1" -le 65535 ]
}

toml_string() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

first_line() {
	"$@" 2>&1 | sed -n '1p'
}

docker_remove() {
	container=$1
	[ -n "$container" ] || return 0
	docker rm -f "$container" >/dev/null 2>&1 || true
}

capture_container_log() {
	container=$1
	destination=$2
	[ -n "$container" ] || return 0
	docker logs "$container" >"$destination" 2>&1 || true
}

stop_trial() {
	stop_resource_sampler
	if [ -n "$SABLE_CONTAINER" ]; then
		capture_container_log "$SABLE_CONTAINER" "$CURRENT_TRIAL_DIRECTORY/sable-server.log"
		docker_remove "$SABLE_CONTAINER"
	fi
	if [ -n "$TECHNITIUM_CONTAINER" ]; then
		capture_container_log "$TECHNITIUM_CONTAINER" "$CURRENT_TRIAL_DIRECTORY/technitium-server.log"
		docker_remove "$TECHNITIUM_CONTAINER"
	fi
	SABLE_CONTAINER=""
	TECHNITIUM_CONTAINER=""
}

cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	stop_trial
	if [ -n "$SABLE_IMAGE_ID" ]; then
		docker image rm "$SABLE_IMAGE" >/dev/null 2>&1 || true
	fi
	if [ "$COMPLETED" != true ] && [ -d "$RESULTS_DIRECTORY" ]; then
		printf '%s\n' "Benchmark interrupted or failed. Partial evidence: $RESULTS_DIRECTORY" >&2
	fi
	exit "$status"
}

validate_inputs() {
	[ -r "$QUERY_FILE" ] || fail "query corpus is not readable: $QUERY_FILE"
	[ -s "$QUERY_FILE" ] || fail "query corpus is empty: $QUERY_FILE"
	awk 'NF != 2 { exit 1 }' "$QUERY_FILE" || fail "every query corpus line must contain exactly a name and record type"
	for value in "$DURATION" "$WARMUP" "$CLIENTS" "$THREADS" "$OUTSTANDING" "$WARMUP_OUTSTANDING" "$TIMEOUT" "$RUNS" "$READY_TIMEOUT" "$DOCKER_START_TIMEOUT" "$CACHE_SIZE" "$MAX_LOSS_PERCENT" "$RESOURCE_SAMPLE_INTERVAL"; do
		is_positive_integer "$value" || fail "numeric benchmark settings must be positive integers (invalid: $value)"
	done
	for port in "$SABLE_PORT" "$SABLE_HTTP_PORT" "$TECHNITIUM_PORT" "$TECHNITIUM_HTTP_PORT"; do
		is_port "$port" || fail "benchmark ports must be integers from 1 through 65535 (invalid: $port)"
	done
	[ "$SABLE_PORT" != "$SABLE_HTTP_PORT" ] || fail "Sable DNS and HTTP ports must differ"
	[ "$TECHNITIUM_PORT" != "$TECHNITIUM_HTTP_PORT" ] || fail "Technitium DNS and HTTP ports must differ"
	if [ "$SABLE_HOST:$SABLE_PORT" = "$TECHNITIUM_HOST:$TECHNITIUM_PORT" ] || \
		[ "$SABLE_HOST:$SABLE_PORT" = "$TECHNITIUM_HOST:$TECHNITIUM_HTTP_PORT" ] || \
		[ "$SABLE_HOST:$SABLE_HTTP_PORT" = "$TECHNITIUM_HOST:$TECHNITIUM_PORT" ] || \
		[ "$SABLE_HOST:$SABLE_HTTP_PORT" = "$TECHNITIUM_HOST:$TECHNITIUM_HTTP_PORT" ]; then
		fail "Sable and Technitium host ports must not overlap"
	fi
	case "$TRANSPORT" in
		udp|tcp) ;;
		*) fail "TRANSPORT must be udp or tcp" ;;
	esac
	case "$MODE" in
		managed|external) ;;
		*) fail "MODE must be managed or external" ;;
	esac
	case "$DNSSEC_OK" in
		true|false) ;;
		*) fail "DNSSEC_OK must be true or false" ;;
	esac
	case "$PLAN_ONLY" in
		true|false) ;;
		*) fail "PLAN_ONLY must be true or false" ;;
	esac
	case "$AUTO_START_DOCKER" in
		true|false) ;;
		*) fail "AUTO_START_DOCKER must be true or false" ;;
	esac
	case "$UPSTREAM" in
		*:* ) ;;
		*) fail "UPSTREAM must include a port, for example 1.1.1.1:53" ;;
	esac
}

create_results_directory() {
	if [ -d "$RESULTS_DIRECTORY" ] && [ -n "$(ls -A "$RESULTS_DIRECTORY" 2>/dev/null)" ]; then
		fail "results directory already exists and is not empty: $RESULTS_DIRECTORY"
	fi
	mkdir -p "$RESULTS_DIRECTORY"
	printf 'product\ttrial\torder\tcompleted\tlost\tqps\taverage_latency_seconds\tlatency_stddev_seconds\trun_time_seconds\traw_output\tsent\tloss_percent\tresponse_codes\n' >"$SUMMARY_FILE"
	printf 'product\tsamples\tmean_qps\tminimum_qps\tmaximum_qps\tmean_average_latency_seconds\ttotal_lost\n' >"$AGGREGATE_FILE"
	printf 'product\ttrial\tsamples\taverage_cpu_percent\tpeak_cpu_percent\taverage_memory_mib\tpeak_memory_mib\tfinal_memory_mib\tfinal_network_io\tfinal_block_io\tfinal_pids\traw_output\n' >"$RESOURCES_FILE"
	printf 'product\ttrial\tsent\tcompleted\tlost\tloss_percent\tqps\taverage_latency_seconds\tresponse_codes\traw_output\n' >"$WARMUP_SUMMARY_FILE"
}

write_sable_config() {
	destination=$1
	cat >"$destination" <<EOF
[server]
http_listen = "0.0.0.0:5380"
dns_listen = ["0.0.0.0:53"]
shutdown_timeout = "15s"

[database]
driver = "sqlite"
dsn = "/state/sable.db"

[resolver]
mode = "forward"
forwarders = ["$UPSTREAM"]
timeout = "${TIMEOUT}s"
cache_size = $CACHE_SIZE
cache_minimum_ttl = 10
cache_maximum_ttl = 604800
cache_negative_ttl = 300
cache_failure_ttl = 10
save_cache = false
serve_stale = true
cache_stale_ttl = 259200
cache_stale_answer_ttl = 30
cache_stale_reset_ttl = 30
cache_stale_max_wait = "1800ms"
cache_prefetch_minimum_ttl = 2
cache_prefetch_trigger_ttl = 9
cache_prefetch_sample_interval = "5m"
cache_prefetch_hits_per_hour = 30
dnssec_validation = true
dnssec_trust_anchor_updates = false

[blocking]
enabled = false
domains = []
allowed_domains = []

[query_log]
enabled = false

[security]
enabled = false
secret_key_file = "/state/sable.key"

[cluster]
data_dir = "/state/cluster"

[config]
watch = false
EOF
}

write_manifest() {
	corpus_sha=$(sha256_file "$QUERY_FILE")
	query_count=$(wc -l <"$QUERY_FILE" | tr -d ' ')
	dnsperf_version=${DNSPERF_VERSION:-not-run}
	dnsperf_path=${DNSPERF_PATH:-not-run}
	dnsperf_sha256=${DNSPERF_SHA256:-not-run}
	docker_version=${DOCKER_VERSION:-not-used}
	docker_cpus=${DOCKER_CPUS:-not-used}
	docker_memory=${DOCKER_MEMORY:-not-used}
	go_version=${GO_VERSION:-not-used}
	cat >"$MANIFEST_FILE" <<EOF
schema_version = 1
run_id = "$(toml_string "$RUN_IDENTIFIER")"
created_at = "$CREATED_AT"
mode = "$(toml_string "$MODE")"
completed = $COMPLETED

[workload]
query_file = "$(toml_string "$QUERY_FILE")"
query_file_sha256 = "$corpus_sha"
query_count = $query_count
runs = $RUNS
warmup_seconds = $WARMUP
warmup_outstanding = $WARMUP_OUTSTANDING
duration_seconds = $DURATION
clients = $CLIENTS
threads = $THREADS
outstanding = $OUTSTANDING
timeout_seconds = $TIMEOUT
maximum_loss_percent = $MAX_LOSS_PERCENT
transport = "$TRANSPORT"
dnssec_ok = $DNSSEC_OK

[comparison]
profile = "forwarding-resolver-no-query-log"
upstream = "$(toml_string "$UPSTREAM")"
blocking = false
query_logging = false
cache_persistence = false
query_rate_limiting = false
cache_size = $CACHE_SIZE
cache_minimum_ttl = 10
cache_maximum_ttl = 604800
cache_negative_ttl = 300
cache_failure_ttl = 10
serve_stale = true
prefetch_trigger_ttl = 9
auto_prefetch_sample_interval = "5m"
auto_prefetch_hits_per_hour = 30
cpu_limit = "$(toml_string "$CPU_LIMIT")"
memory_limit = "$(toml_string "$MEMORY_LIMIT")"
isolation = "fresh state and fresh containers for every trial"
resource_sampling = "isolated Docker stats polling during each measured interval"
resource_sample_interval_seconds = $RESOURCE_SAMPLE_INTERVAL
cache_profile_note = "Sable is explicitly aligned to the Technitium 15.4 fresh-install cache profile; Technitium state is retained with the evidence"

[sable]
image = "$(toml_string "$SABLE_IMAGE")"
image_id = "$(toml_string "$SABLE_IMAGE_ID")"
binary_sha256 = "$(toml_string "$SABLE_BINARY_SHA256")"
endpoint = "$(toml_string "$SABLE_HOST:$SABLE_PORT")"

[technitium]
image = "$(toml_string "$TECHNITIUM_IMAGE")"
image_id = "$(toml_string "$TECHNITIUM_IMAGE_ID")"
image_digest = "$(toml_string "$TECHNITIUM_IMAGE_DIGEST")"
endpoint = "$(toml_string "$TECHNITIUM_HOST:$TECHNITIUM_PORT")"
first_start_environment = true
settings_api_verified = $TECHNITIUM_SETTINGS_API_VERIFIED
qpm_limits_disabled = $TECHNITIUM_SETTINGS_API_VERIFIED

[tools]
dnsperf = "$(toml_string "$dnsperf_version")"
dnsperf_path = "$(toml_string "$dnsperf_path")"
dnsperf_sha256 = "$(toml_string "$dnsperf_sha256")"
docker = "$(toml_string "$docker_version")"
docker_cpus = "$(toml_string "$docker_cpus")"
docker_memory_bytes = "$(toml_string "$docker_memory")"
docker_auto_started = $DOCKER_AUTO_STARTED
go = "$(toml_string "$go_version")"

[host]
os = "$(toml_string "$(uname -s)")"
architecture = "$(toml_string "$(uname -m)")"
kernel = "$(toml_string "$(uname -r)")"

[harness]
compare_script_sha256 = "$(sha256_file "$SCRIPT_DIRECTORY/compare.sh")"
sable_dockerfile_sha256 = "$(sha256_file "$SCRIPT_DIRECTORY/Dockerfile.sable")"
EOF
}

docker_architecture() {
	architecture=$(docker info --format '{{.Architecture}}')
	case "$architecture" in
		x86_64|amd64) printf '%s' amd64 ;;
		aarch64|arm64) printf '%s' arm64 ;;
		*) fail "unsupported Docker architecture: $architecture" ;;
	esac
}

ensure_docker_daemon() {
	if docker info >/dev/null 2>&1; then
		return 0
	fi
	if [ "$AUTO_START_DOCKER" != true ]; then
		fail "Docker is installed but its daemon is not running; start it or rerun with AUTO_START_DOCKER=true"
	fi

	started_runtime=""
	if command -v orbctl >/dev/null 2>&1 && [ "$(docker context show 2>/dev/null || true)" = orbstack ]; then
		printf '%s\n' "Docker is stopped; starting OrbStack..."
		if [ "$(uname -s)" = Darwin ] && [ -d /Applications/OrbStack.app ] && command -v open >/dev/null 2>&1; then
			if ! open -g /Applications/OrbStack.app >/dev/null 2>&1; then
				printf '%s\n' "OrbStack app launch failed; falling back to orbctl."
				orbctl start >/dev/null 2>&1 &
			fi
		else
			orbctl start >/dev/null 2>&1 &
		fi
		started_runtime=OrbStack
	elif [ "$(uname -s)" = Darwin ] && [ -d /Applications/Docker.app ] && command -v open >/dev/null 2>&1; then
		printf '%s\n' "Docker is stopped; starting Docker Desktop..."
		open -g /Applications/Docker.app || fail "could not start Docker Desktop; open it and retry"
		started_runtime="Docker Desktop"
	else
		fail "Docker is installed but its daemon is not running; start the local container runtime and retry"
	fi

	elapsed=0
	while [ "$elapsed" -lt "$DOCKER_START_TIMEOUT" ]; do
		if docker info >/dev/null 2>&1; then
			DOCKER_AUTO_STARTED=true
			printf '%s\n' "$started_runtime is ready."
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	fail "$started_runtime did not make Docker ready within ${DOCKER_START_TIMEOUT}s"
}

prepare_images() {
	case "$PULL_TECHNITIUM" in
		always) docker pull "$TECHNITIUM_IMAGE" ;;
		if-missing)
			if ! docker image inspect "$TECHNITIUM_IMAGE" >/dev/null 2>&1; then
				docker pull "$TECHNITIUM_IMAGE"
			fi
			;;
		never) docker image inspect "$TECHNITIUM_IMAGE" >/dev/null 2>&1 || fail "Technitium image is not available locally: $TECHNITIUM_IMAGE" ;;
		*) fail "PULL_TECHNITIUM must be always, if-missing, or never" ;;
	esac

	build_directory="$RESULTS_DIRECTORY/sable-image"
	mkdir -p "$build_directory"
	linux_architecture=$(docker_architecture)
	printf '%s\n' "Building the current Sable source for linux/$linux_architecture..."
	(
		cd "$REPOSITORY_DIRECTORY"
		env CGO_ENABLED=0 GOOS=linux GOARCH="$linux_architecture" \
			go build -trimpath -o "$build_directory/sable" ./cmd/sable
	)
	cp "$SCRIPT_DIRECTORY/Dockerfile.sable" "$build_directory/Dockerfile"
	docker build --pull=false --tag "$SABLE_IMAGE" "$build_directory"

	SABLE_BINARY_SHA256=$(sha256_file "$build_directory/sable")
	SABLE_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$SABLE_IMAGE")
	TECHNITIUM_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$TECHNITIUM_IMAGE")
	TECHNITIUM_IMAGE_DIGEST=$(docker image inspect --format '{{join .RepoDigests ","}}' "$TECHNITIUM_IMAGE")
}

start_trial() {
	trial=$1
	CURRENT_TRIAL_DIRECTORY="$RESULTS_DIRECTORY/trial-$(printf '%02d' "$trial")"
	mkdir -p "$CURRENT_TRIAL_DIRECTORY/sable-state" "$CURRENT_TRIAL_DIRECTORY/technitium-state"
	write_sable_config "$CURRENT_TRIAL_DIRECTORY/sable.toml"

	SABLE_CONTAINER="sable-benchmark-$RUN_IDENTIFIER-$trial"
	TECHNITIUM_CONTAINER="technitium-benchmark-$RUN_IDENTIFIER-$trial"
	technitium_forwarder=${UPSTREAM%:53}
	cat >"$CURRENT_TRIAL_DIRECTORY/technitium.env" <<EOF
DNS_SERVER_DOMAIN=technitium.benchmark.invalid
DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=0.0.0.0
DNS_SERVER_WEB_SERVICE_HTTP_PORT=5380
DNS_SERVER_RECURSION=Allow
DNS_SERVER_ENABLE_BLOCKING=false
DNS_SERVER_ALLOW_TXT_BLOCKING_REPORT=false
DNS_SERVER_FORWARDERS=$technitium_forwarder
DNS_SERVER_FORWARDER_PROTOCOL=Udp
DNS_SERVER_STATS_ENABLE_IN_MEMORY_STATS=true
EOF

	docker run --detach --name "$SABLE_CONTAINER" \
		--cpus "$CPU_LIMIT" --memory "$MEMORY_LIMIT" \
		--publish "$SABLE_HOST:$SABLE_PORT:53/udp" \
		--publish "$SABLE_HOST:$SABLE_PORT:53/tcp" \
		--publish "$SABLE_HOST:$SABLE_HTTP_PORT:5380/tcp" \
		--volume "$CURRENT_TRIAL_DIRECTORY/sable.toml:/sable.toml:ro" \
		--volume "$CURRENT_TRIAL_DIRECTORY/sable-state:/state" \
		"$SABLE_IMAGE" serve --config /sable.toml >/dev/null

	docker run --detach --name "$TECHNITIUM_CONTAINER" \
		--cpus "$CPU_LIMIT" --memory "$MEMORY_LIMIT" \
		--publish "$TECHNITIUM_HOST:$TECHNITIUM_PORT:53/udp" \
		--publish "$TECHNITIUM_HOST:$TECHNITIUM_PORT:53/tcp" \
		--publish "$TECHNITIUM_HOST:$TECHNITIUM_HTTP_PORT:5380/tcp" \
		--volume "$CURRENT_TRIAL_DIRECTORY/technitium-state:/etc/dns" \
		--env DNS_SERVER_DOMAIN=technitium.benchmark.invalid \
		--env DNS_SERVER_ADMIN_PASSWORD=benchmark-only \
		--env DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=0.0.0.0 \
		--env DNS_SERVER_WEB_SERVICE_HTTP_PORT=5380 \
		--env DNS_SERVER_RECURSION=Allow \
		--env DNS_SERVER_ENABLE_BLOCKING=false \
		--env DNS_SERVER_ALLOW_TXT_BLOCKING_REPORT=false \
		--env DNS_SERVER_FORWARDERS="$technitium_forwarder" \
		--env DNS_SERVER_FORWARDER_PROTOCOL=Udp \
		--env DNS_SERVER_STATS_ENABLE_IN_MEMORY_STATS=true \
		"$TECHNITIUM_IMAGE" >/dev/null
}

wait_for_dns() {
	label=$1
	host=$2
	port=$3
	container=$4
	elapsed=0
	while [ "$elapsed" -lt "$READY_TIMEOUT" ]; do
		if ! docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
			docker logs "$container" >&2 || true
			fail "$label exited before becoming ready"
		fi
		if dig @"$host" -p "$port" example.com A +time=1 +tries=1 +noall +comments >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
	docker logs "$container" >&2 || true
	fail "$label did not answer DNS within ${READY_TIMEOUT}s"
}

configure_technitium() {
	base_url="http://$TECHNITIUM_HOST:$TECHNITIUM_HTTP_PORT"
	login_response=$(curl --fail --silent --show-error --request POST \
		--data-urlencode 'user=admin' \
		--data-urlencode 'pass=benchmark-only' \
		--data-urlencode 'includeInfo=false' \
		"$base_url/api/user/login")
	token=$(printf '%s' "$login_response" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
	[ -n "$token" ] || fail "Technitium API login failed"

	settings_response=$(curl --fail --silent --show-error --request POST \
		--header "Authorization: Bearer $token" \
		--data-urlencode 'qpmPrefixLimitsIPv4=false' \
		--data-urlencode 'qpmPrefixLimitsIPv6=false' \
		--data-urlencode 'saveCache=false' \
		"$base_url/api/settings/set")
	printf '%s\n' "$settings_response" >"$CURRENT_TRIAL_DIRECTORY/technitium-settings-set.json"
	printf '%s' "$settings_response" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' || \
		fail "Technitium rejected benchmark settings; see $CURRENT_TRIAL_DIRECTORY/technitium-settings-set.json"

	settings_response=$(curl --fail --silent --show-error \
		--header "Authorization: Bearer $token" \
		"$base_url/api/settings/get")
	printf '%s\n' "$settings_response" >"$CURRENT_TRIAL_DIRECTORY/technitium-settings.json"
	printf '%s' "$settings_response" | grep -Eq '"qpmPrefixLimitsIPv4"[[:space:]]*:[[:space:]]*\[\]' || \
		fail "Technitium IPv4 QPM limits remain enabled; see $CURRENT_TRIAL_DIRECTORY/technitium-settings.json"
	printf '%s' "$settings_response" | grep -Eq '"qpmPrefixLimitsIPv6"[[:space:]]*:[[:space:]]*\[\]' || \
		fail "Technitium IPv6 QPM limits remain enabled; see $CURRENT_TRIAL_DIRECTORY/technitium-settings.json"
	printf '%s' "$settings_response" | grep -Eq '"saveCache"[[:space:]]*:[[:space:]]*false' || \
		fail "Technitium cache persistence remains enabled; see $CURRENT_TRIAL_DIRECTORY/technitium-settings.json"
	printf '%s' "$settings_response" | grep -Eq '"enableBlocking"[[:space:]]*:[[:space:]]*false' || \
		fail "Technitium blocking remains enabled; see $CURRENT_TRIAL_DIRECTORY/technitium-settings.json"
	printf '%s' "$settings_response" | grep -Eq '"logQueries"[[:space:]]*:[[:space:]]*false' || \
		fail "Technitium query logging remains enabled; see $CURRENT_TRIAL_DIRECTORY/technitium-settings.json"
	TECHNITIUM_SETTINGS_API_VERIFIED=true
}

probe_status() {
	label=$1
	host=$2
	port=$3
	name=$4
	type=$5
	destination=$6
	dig @"$host" -p "$port" "$name" "$type" +time="$TIMEOUT" +tries=1 +noall +comments +answer >"$destination"
	status=$(sed -n 's/.*status: \([^,]*\),.*/\1/p' "$destination" | sed -n '1p')
	[ -n "$status" ] || fail "$label probe did not return a DNS status for $name $type"
	printf '%s' "$status"
}

verify_trial() {
	trial=$1
	probe_file="$CURRENT_TRIAL_DIRECTORY/probes.tsv"
	printf 'name\ttype\tsable_status\ttechnitium_status\n' >"$probe_file"
	for probe in 'example.com A' 'example.invalid A' 'cloudflare.com AAAA'; do
		name=${probe% *}
		type=${probe#* }
		sable_status=$(probe_status Sable "$SABLE_HOST" "$SABLE_PORT" "$name" "$type" "$CURRENT_TRIAL_DIRECTORY/probe-sable-$name-$type.txt")
		technitium_status=$(probe_status Technitium "$TECHNITIUM_HOST" "$TECHNITIUM_PORT" "$name" "$type" "$CURRENT_TRIAL_DIRECTORY/probe-technitium-$name-$type.txt")
		printf '%s\t%s\t%s\t%s\n' "$name" "$type" "$sable_status" "$technitium_status" >>"$probe_file"
		[ "$sable_status" = "$technitium_status" ] || fail "preflight RCODE mismatch in trial $trial for $name $type: Sable=$sable_status Technitium=$technitium_status"
	done
}

dnsperf_options() {
	options=""
	if [ "$DNSSEC_OK" = true ]; then
		options="$options -D"
	fi
	if dnsperf -H 2>&1 | grep -q 'latency-histogram'; then
		options="$options -O latency-histogram"
	fi
	printf '%s' "$options"
}

record_dnsperf_metadata() {
	DNSPERF_PATH=$(command -v dnsperf)
	DNSPERF_SHA256=$(sha256_file "$DNSPERF_PATH")
	if command -v brew >/dev/null 2>&1; then
		brew_dnsperf_prefix=$(brew --prefix dnsperf 2>/dev/null || true)
		case "$DNSPERF_PATH" in
			"$brew_dnsperf_prefix"/*) DNSPERF_VERSION=$(brew list --versions dnsperf 2>/dev/null | sed -n '1p') ;;
		esac
	fi
	DNSPERF_VERSION=${DNSPERF_VERSION:-"dnsperf executable sha256:$DNSPERF_SHA256"}
}

run_dnsperf() {
	label=$1
	product=$2
	host=$3
	port=$4
	trial=$5
	order=$6
	dnsperf_raw_file="$CURRENT_TRIAL_DIRECTORY/$product-dnsperf.txt"
	warmup_raw_file="$CURRENT_TRIAL_DIRECTORY/$product-warmup.txt"
	extra_options=$(dnsperf_options)

	printf '%s\n' "$label warmup ($host:$port, ${WARMUP}s)"
	# Intentional word splitting: dnsperf_options returns only harness-owned flags.
	# shellcheck disable=SC2086
	dnsperf -m "$TRANSPORT" -s "$host" -p "$port" -d "$QUERY_FILE" -l "$WARMUP" \
		-c 1 -T 1 -q "$WARMUP_OUTSTANDING" -t "$TIMEOUT" $extra_options \
		>"$warmup_raw_file" 2>&1
	record_warmup "$product" "$trial" "$warmup_raw_file"

	printf '%s\n' "$label measured run (${DURATION}s)"
	if [ "$MODE" = managed ]; then
		start_resource_sampler "$product" "$trial"
	fi
	# shellcheck disable=SC2086
	dnsperf -m "$TRANSPORT" -s "$host" -p "$port" -d "$QUERY_FILE" -l "$DURATION" \
		-c "$CLIENTS" -T "$THREADS" -q "$OUTSTANDING" -t "$TIMEOUT" $extra_options \
		>"$dnsperf_raw_file" 2>&1
	if [ "$MODE" = managed ]; then
		stop_resource_sampler
	fi
	awk '/Queries sent:|Queries completed:|Queries lost:|Response codes:|Run time \(s\):|Queries per second:|Average Latency|Latency StdDev/' "$dnsperf_raw_file"

	completed=$(awk -F: '/Queries completed:/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$dnsperf_raw_file")
	lost=$(awk -F: '/Queries lost:/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$dnsperf_raw_file")
	qps=$(awk -F: '/Queries per second:/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$dnsperf_raw_file")
	average=$(awk -F: '/Average Latency/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$dnsperf_raw_file")
	stddev=$(awk -F: '/Latency StdDev/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$dnsperf_raw_file")
	runtime=$(awk -F: '/Run time \(s\):/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$dnsperf_raw_file")
	sent=$(awk -F: '/Queries sent:/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$dnsperf_raw_file")
	response_codes=$(sed -n 's/^[[:space:]]*Response codes:[[:space:]]*//p' "$dnsperf_raw_file" | sed -n '1p')
	[ -n "$sent" ] && [ -n "$lost" ] || fail "$label produced an incomplete dnsperf result"
	loss_percent=$(awk -v lost="$lost" -v sent="$sent" 'BEGIN { if (sent == 0) print 100; else printf "%.6f", (lost * 100) / sent }')
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$product" "$trial" "$order" "${completed:-unknown}" "${lost:-unknown}" "${qps:-unknown}" \
		"${average:-unknown}" "${stddev:-unknown}" "${runtime:-unknown}" "${dnsperf_raw_file#$RESULTS_DIRECTORY/}" \
		"$sent" "$loss_percent" "${response_codes:-unknown}" >>"$SUMMARY_FILE"
	if awk -v actual="$loss_percent" -v maximum="$MAX_LOSS_PERCENT" 'BEGIN { exit !(actual > maximum) }'; then
		fail "$label trial $trial lost $lost of $sent queries ($loss_percent%), exceeding the ${MAX_LOSS_PERCENT}% validity threshold; raw evidence: $dnsperf_raw_file"
	fi
}

record_warmup() {
	warmup_product=$1
	warmup_trial=$2
	warmup_evidence_file=$3
	warmup_sent=$(awk -F: '/Queries sent:/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$warmup_evidence_file")
	warmup_completed=$(awk -F: '/Queries completed:/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$warmup_evidence_file")
	warmup_lost=$(awk -F: '/Queries lost:/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$warmup_evidence_file")
	warmup_qps=$(awk -F: '/Queries per second:/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$warmup_evidence_file")
	warmup_average=$(awk -F: '/Average Latency/{gsub(/^[ \t]+/, "", $2); sub(/[ \t].*/, "", $2); print $2; exit}' "$warmup_evidence_file")
	warmup_response_codes=$(sed -n 's/^[[:space:]]*Response codes:[[:space:]]*//p' "$warmup_evidence_file" | sed -n '1p')
	[ -n "$warmup_sent" ] && [ -n "$warmup_completed" ] && [ -n "$warmup_lost" ] || fail "$warmup_product warmup produced an incomplete dnsperf result"
	warmup_loss_percent=$(awk -v lost="$warmup_lost" -v sent="$warmup_sent" 'BEGIN { if (sent == 0) print 100; else printf "%.6f", (lost * 100) / sent }')
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$warmup_product" "$warmup_trial" "$warmup_sent" "$warmup_completed" "$warmup_lost" "$warmup_loss_percent" \
		"${warmup_qps:-unknown}" "${warmup_average:-unknown}" "${warmup_response_codes:-unknown}" \
		"${warmup_evidence_file#$RESULTS_DIRECTORY/}" >>"$WARMUP_SUMMARY_FILE"
}

resource_container() {
	product=$1
	case "$product" in
		sable) printf '%s' "$SABLE_CONTAINER" ;;
		technitium) printf '%s' "$TECHNITIUM_CONTAINER" ;;
		*) fail "unknown benchmark product: $product" ;;
	esac
}

start_resource_sampler() {
	product=$1
	trial=$2
	container=$(resource_container "$product")
	RESOURCE_SAMPLER_FILE="$CURRENT_TRIAL_DIRECTORY/$product-resources.tsv"
	RESOURCE_SAMPLER_STOP_FILE="$CURRENT_TRIAL_DIRECTORY/$product-resources.stop"
	error_file="$CURRENT_TRIAL_DIRECTORY/$product-resources-error.log"
	printf 'sampled_at\tcpu_percent\tmemory_usage\tmemory_percent\tnetwork_io\tblock_io\tpids\n' >"$RESOURCE_SAMPLER_FILE"
	: >"$error_file"
	rm -f "$RESOURCE_SAMPLER_STOP_FILE"
	(
		while [ ! -e "$RESOURCE_SAMPLER_STOP_FILE" ]; do
			sampled_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
			if sample=$(docker stats --no-stream \
				--format '{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}' \
				"$container" </dev/null 2>>"$error_file"); then
				printf '%s\t%s\n' "$sampled_at" "$sample" >>"$RESOURCE_SAMPLER_FILE"
			else
				exit 1
			fi
			sleep "$RESOURCE_SAMPLE_INTERVAL"
		done
	) </dev/null &
	RESOURCE_SAMPLER_PID=$!
	RESOURCE_SAMPLER_PRODUCT=$product
	RESOURCE_SAMPLER_TRIAL=$trial
}

stop_resource_sampler() {
	[ -n "$RESOURCE_SAMPLER_PID" ] || return 0
	: >"$RESOURCE_SAMPLER_STOP_FILE"
	wait "$RESOURCE_SAMPLER_PID" >/dev/null 2>&1 || true
	summarize_resource_samples "$RESOURCE_SAMPLER_PRODUCT" "$RESOURCE_SAMPLER_TRIAL" "$RESOURCE_SAMPLER_FILE"
	rm -f "$RESOURCE_SAMPLER_STOP_FILE"
	RESOURCE_SAMPLER_PID=""
	RESOURCE_SAMPLER_FILE=""
	RESOURCE_SAMPLER_STOP_FILE=""
}

summarize_resource_samples() {
	resource_product=$1
	resource_trial=$2
	resource_evidence_file=$3
	row=$(awk -F '\t' '
		function memory_mib(text, parts, value) {
			split(text, parts, " / ")
			value = parts[1]
			if (value ~ /GiB$/) { sub(/GiB$/, "", value); return value * 1024 }
			if (value ~ /MiB$/) { sub(/MiB$/, "", value); return value + 0 }
			if (value ~ /KiB$/) { sub(/KiB$/, "", value); return value / 1024 }
			if (value ~ /kB$/) { sub(/kB$/, "", value); return value / 1024 }
			if (value ~ /B$/) { sub(/B$/, "", value); return value / 1048576 }
			return value + 0
		}
		NR == 1 { next }
		$2 !~ /^[0-9]+([.][0-9]+)?%$/ { next }
		{
			cpu = $2; sub(/%$/, "", cpu)
			memory = memory_mib($3)
			samples++
			cpu_total += cpu
			memory_total += memory
			if (samples == 1 || cpu > peak_cpu) peak_cpu = cpu
			if (samples == 1 || memory > peak_memory) peak_memory = memory
			final_memory = memory
			final_network = $5
			final_block = $6
			final_pids = $7
		}
		END {
			if (samples > 0)
				printf "%d\t%.6f\t%.6f\t%.6f\t%.6f\t%.6f\t%s\t%s\t%s", samples, cpu_total / samples, peak_cpu, memory_total / samples, peak_memory, final_memory, final_network, final_block, final_pids
		}
	' "$resource_evidence_file")
	[ -n "$row" ] || fail "resource sampler did not capture data for $resource_product trial $resource_trial"
	printf '%s\t%s\t%s\t%s\n' "$resource_product" "$resource_trial" "$row" "${resource_evidence_file#$RESULTS_DIRECTORY/}" >>"$RESOURCES_FILE"
}

write_aggregate() {
	awk -F '\t' 'BEGIN {
		OFS = "\t"
		products[1] = "sable"
		products[2] = "technitium"
	}
	NR > 1 && $6 != "unknown" && $7 != "unknown" {
		product = $1
		qps = $6 + 0
		latency = $7 + 0
		samples[product]++
		total_qps[product] += qps
		total_latency[product] += latency
		if (samples[product] == 1 || qps < minimum_qps[product]) minimum_qps[product] = qps
		if (samples[product] == 1 || qps > maximum_qps[product]) maximum_qps[product] = qps
		if ($5 != "unknown") total_lost[product] += $5 + 0
	}
	END {
		for (ordinal = 1; ordinal <= 2; ordinal++) {
			product = products[ordinal]
			if (samples[product] > 0) {
				print product, samples[product], total_qps[product] / samples[product], minimum_qps[product], maximum_qps[product], total_latency[product] / samples[product], total_lost[product]
			}
		}
	}' "$SUMMARY_FILE" >>"$AGGREGATE_FILE"
}

print_final_summary() {
	printf '\nBenchmark summary\n\n'
	awk -F '\t' -v summary="$SUMMARY_FILE" -v resources="$RESOURCES_FILE" -v warmups="$WARMUP_SUMMARY_FILE" -v maximum_loss="$MAX_LOSS_PERCENT" '
		function grouped(value, text, result) {
			text = sprintf("%.0f", value)
			result = ""
			while (length(text) > 3) {
				result = "," substr(text, length(text) - 2) result
				text = substr(text, 1, length(text) - 3)
			}
			return text result
		}
		function canonical_response(value) {
			gsub(/ [0-9]+ \(/, " (", value)
			return value
		}
		$1 == "product" { next }
		FILENAME == summary {
			product = $1
			trial = $2
			qps_total[product] += $6
			latency_total[product] += $7
			lost_total[product] += $5
			sent_total[product] += $11
			runs[product]++
			responses[product, trial] = canonical_response($13)
			trials[trial] = 1
			next
		}
		FILENAME == resources {
			product = $1
			cpu_average_total[product] += $4
			resource_runs[product]++
			if (!(product in peak_cpu) || $5 > peak_cpu[product]) peak_cpu[product] = $5
			if (!(product in peak_memory) || $7 > peak_memory[product]) peak_memory[product] = $7
			next
		}
		FILENAME == warmups {
			warmup_lost[$1] += $5
			next
		}
		END {
			if (!runs["sable"] || !runs["technitium"]) {
				print "Summary unavailable: both products did not produce measured results."
				exit
			}
			sable_qps = qps_total["sable"] / runs["sable"]
			technitium_qps = qps_total["technitium"] / runs["technitium"]
			throughput_delta = (sable_qps / technitium_qps - 1) * 100
			if (throughput_delta >= 0)
				printf "Throughput: **%s qps** vs Technitium **%s qps** — Sable +%.2f%%.\n", grouped(sable_qps), grouped(technitium_qps), throughput_delta
			else
				printf "Throughput: **%s qps** vs Technitium **%s qps** — Sable %.2f%% lower.\n", grouped(sable_qps), grouped(technitium_qps), -throughput_delta

			sable_latency = latency_total["sable"] * 1000 / runs["sable"]
			technitium_latency = latency_total["technitium"] * 1000 / runs["technitium"]
			latency_delta = (sable_latency / technitium_latency - 1) * 100
			if (latency_delta <= 0)
				printf "Average latency: **%.3f ms** vs **%.3f ms** — Sable %.0f%% lower.\n", sable_latency, technitium_latency, -latency_delta
			else
				printf "Average latency: **%.3f ms** vs **%.3f ms** — Sable %.0f%% higher.\n", sable_latency, technitium_latency, latency_delta

			sable_loss = lost_total["sable"] * 100 / sent_total["sable"]
			technitium_loss = lost_total["technitium"] * 100 / sent_total["technitium"]
			if (sable_loss <= maximum_loss && technitium_loss <= maximum_loss)
				printf "Loss: %.2f%% vs %.2f%%, both below the %g%% threshold.\n", sable_loss, technitium_loss, maximum_loss
			else
				printf "Loss: %.2f%% vs %.2f%%.\n", sable_loss, technitium_loss

			response_match = 1
			for (trial in trials)
				if (responses["sable", trial] != responses["technitium", trial]) response_match = 0
			if (response_match)
				print "Response-code distributions matched exactly."
			else
				print "Response-code distributions differed; inspect the per-trial evidence."

			if (warmup_lost["sable"] == 0 && warmup_lost["technitium"] == 0)
				print "Warmups completed with zero loss."
			else
				printf "Warmup loss: Sable %d queries, Technitium %d queries.\n", warmup_lost["sable"], warmup_lost["technitium"]

			if (resource_runs["sable"] && resource_runs["technitium"]) {
				printf "Sable used **%.1f MiB** versus Technitium **%.1f MiB** peak memory during measured load.\n", peak_memory["sable"], peak_memory["technitium"]
				printf "Average CPU: Sable **%.1f%%** (%.1f%% peak) versus Technitium **%.1f%%** (%.1f%% peak).\n", cpu_average_total["sable"] / resource_runs["sable"], peak_cpu["sable"], cpu_average_total["technitium"] / resource_runs["technitium"], peak_cpu["technitium"]
			}
		}
	' "$SUMMARY_FILE" "$RESOURCES_FILE" "$WARMUP_SUMMARY_FILE"
}

run_managed() {
	require_command docker ""
	require_command go ""
	require_command dig ""
	require_command curl ""
	require_command dnsperf " (macOS: brew install dnsperf)"

	record_dnsperf_metadata
	GO_VERSION=$(first_line go version)
	write_manifest
	ensure_docker_daemon
	DOCKER_VERSION=$(docker version --format '{{.Server.Version}}')
	DOCKER_CPUS=$(docker info --format '{{.NCPU}}')
	DOCKER_MEMORY=$(docker info --format '{{.MemTotal}}')
	write_manifest
	prepare_images
	write_manifest

	trial=1
	while [ "$trial" -le "$RUNS" ]; do
		printf '\nTrial %s of %s: starting fresh containers and empty state\n' "$trial" "$RUNS"
		start_trial "$trial"
		wait_for_dns Sable "$SABLE_HOST" "$SABLE_PORT" "$SABLE_CONTAINER"
		wait_for_dns Technitium "$TECHNITIUM_HOST" "$TECHNITIUM_PORT" "$TECHNITIUM_CONTAINER"
		configure_technitium
		verify_trial "$trial"

		if [ $((trial % 2)) -eq 1 ]; then
			run_dnsperf Sable sable "$SABLE_HOST" "$SABLE_PORT" "$trial" 1
			run_dnsperf Technitium technitium "$TECHNITIUM_HOST" "$TECHNITIUM_PORT" "$trial" 2
		else
			run_dnsperf Technitium technitium "$TECHNITIUM_HOST" "$TECHNITIUM_PORT" "$trial" 1
			run_dnsperf Sable sable "$SABLE_HOST" "$SABLE_PORT" "$trial" 2
		fi
		stop_trial
		trial=$((trial + 1))
	done
}

run_external() {
	require_command dnsperf " (macOS: brew install dnsperf)"
	record_dnsperf_metadata
	printf '%s\n' "WARNING: external mode cannot verify clean state, resource parity, or server configuration." >&2
	write_manifest
	trial=1
	while [ "$trial" -le "$RUNS" ]; do
		CURRENT_TRIAL_DIRECTORY="$RESULTS_DIRECTORY/trial-$(printf '%02d' "$trial")"
		mkdir -p "$CURRENT_TRIAL_DIRECTORY"
		if [ $((trial % 2)) -eq 1 ]; then
			run_dnsperf Sable sable "$SABLE_HOST" "$SABLE_PORT" "$trial" 1
			run_dnsperf Technitium technitium "$TECHNITIUM_HOST" "$TECHNITIUM_PORT" "$trial" 2
		else
			run_dnsperf Technitium technitium "$TECHNITIUM_HOST" "$TECHNITIUM_PORT" "$trial" 1
			run_dnsperf Sable sable "$SABLE_HOST" "$SABLE_PORT" "$trial" 2
		fi
		trial=$((trial + 1))
	done
}

case "$SUMMARY_ONLY" in
	true)
		[ -r "$SUMMARY_FILE" ] || fail "summary file is not readable: $SUMMARY_FILE"
		[ -r "$RESOURCES_FILE" ] || fail "resource summary is not readable: $RESOURCES_FILE"
		[ -r "$WARMUP_SUMMARY_FILE" ] || fail "warmup summary is not readable: $WARMUP_SUMMARY_FILE"
		print_final_summary
		exit 0
		;;
	false) ;;
	*) fail "SUMMARY_ONLY must be true or false" ;;
esac

validate_inputs
create_results_directory
trap cleanup EXIT HUP INT TERM

if [ "$PLAN_ONLY" = true ]; then
	mkdir -p "$RESULTS_DIRECTORY/plan"
	write_sable_config "$RESULTS_DIRECTORY/plan/sable.toml"
	write_manifest
	COMPLETED=true
	write_manifest
	printf '%s\n' "Benchmark plan generated without starting servers: $RESULTS_DIRECTORY"
	exit 0
fi

printf '%s\n' "Corpus: $QUERY_FILE ($(wc -l <"$QUERY_FILE" | tr -d ' ') queries, sha256=$(sha256_file "$QUERY_FILE"))"
printf '%s\n' "Profile: clean forwarding resolver, upstream=$UPSTREAM, blocking=false, query_log=false"
printf '%s\n' "Load: clients=$CLIENTS threads=$THREADS outstanding=$OUTSTANDING timeout=${TIMEOUT}s transport=$TRANSPORT"
printf '%s\n' "Warmup: ${WARMUP}s with one client, one thread, outstanding=$WARMUP_OUTSTANDING"
printf '%s\n' "Validity: measured DNS loss must not exceed ${MAX_LOSS_PERCENT}%"
printf '%s\n' "Evidence: $RESULTS_DIRECTORY"

if [ "$MODE" = managed ]; then
	run_managed
else
	run_external
fi

write_aggregate
COMPLETED=true
write_manifest
print_final_summary
printf '\n%s\n' "Benchmark complete. Aggregate: $AGGREGATE_FILE"
printf '%s\n' "Per-trial summary: $SUMMARY_FILE"
