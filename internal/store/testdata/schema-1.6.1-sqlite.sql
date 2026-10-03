-- The schema Sable 1.6.1 created on a new sqlite database, taken from store.Open
-- at v1.6.1. migrate_test.go upgrades it.

CREATE TABLE sable_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE sable_query_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
	occurred_at TIMESTAMP NOT NULL,
	client_ip TEXT NOT NULL,
	client_ip_key TEXT NOT NULL DEFAULT '',
	name TEXT NOT NULL,
	name_key TEXT NOT NULL DEFAULT '',
    record_type INTEGER NOT NULL,
    class INTEGER NOT NULL,
    response_code INTEGER NOT NULL,
    source TEXT NOT NULL,
	protocol TEXT NOT NULL DEFAULT '',
	answer TEXT NOT NULL DEFAULT '',
	decision TEXT NOT NULL DEFAULT '{}',
    duration_us BIGINT NOT NULL
);

CREATE TABLE sable_query_log_rollup (
    bucket_start TIMESTAMP NOT NULL,
    dimension TEXT NOT NULL,
    value TEXT NOT NULL,
    hits BIGINT NOT NULL,
    PRIMARY KEY (bucket_start, dimension, value)
);

CREATE TABLE sable_server_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TIMESTAMP NOT NULL,
    level INTEGER NOT NULL,
    message TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE sable_dns_cache (
    request_wire BLOB PRIMARY KEY,
    response_wire BLOB NOT NULL,
    stored_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    stale_until TIMESTAMP
);

CREATE INDEX sable_query_log_occurred_at_idx
ON sable_query_log (occurred_at);

CREATE INDEX sable_server_log_occurred_at_idx
ON sable_server_log (occurred_at);

CREATE TABLE sable_query_stats (
    bucket_start BIGINT PRIMARY KEY,
    queries BIGINT NOT NULL DEFAULT 0,
    no_error BIGINT NOT NULL DEFAULT 0,
    server_failures BIGINT NOT NULL DEFAULT 0,
    nx_domain BIGINT NOT NULL DEFAULT 0,
    refused BIGINT NOT NULL DEFAULT 0,
    blocked BIGINT NOT NULL DEFAULT 0,
    cache_hits BIGINT NOT NULL DEFAULT 0,
    cache_misses BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE sable_query_stats_totals (
    id INTEGER PRIMARY KEY,
    queries BIGINT NOT NULL DEFAULT 0,
    no_error BIGINT NOT NULL DEFAULT 0,
    server_failures BIGINT NOT NULL DEFAULT 0,
    nx_domain BIGINT NOT NULL DEFAULT 0,
    refused BIGINT NOT NULL DEFAULT 0,
    blocked BIGINT NOT NULL DEFAULT 0,
    failures BIGINT NOT NULL DEFAULT 0,
    upstream_errors BIGINT NOT NULL DEFAULT 0,
    cache_hits BIGINT NOT NULL DEFAULT 0,
    cache_misses BIGINT NOT NULL DEFAULT 0,
    routed_queries BIGINT NOT NULL DEFAULT 0,
    local_answers BIGINT NOT NULL DEFAULT 0,
    authoritative_answers BIGINT NOT NULL DEFAULT 0,
    dnssec_secure BIGINT NOT NULL DEFAULT 0,
    dnssec_insecure BIGINT NOT NULL DEFAULT 0,
    dnssec_bogus BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE sable_query_log_rollup_hour (
    dimension TEXT NOT NULL,
    bucket_start TIMESTAMP NOT NULL,
    value TEXT NOT NULL,
    hits BIGINT NOT NULL,
    PRIMARY KEY (dimension, bucket_start, value)
);

CREATE TABLE sable_query_log_rollup_day (
    dimension TEXT NOT NULL,
    bucket_start TIMESTAMP NOT NULL,
    value TEXT NOT NULL,
    hits BIGINT NOT NULL,
    PRIMARY KEY (dimension, bucket_start, value)
);

CREATE TABLE sable_client_seen (
    client_key TEXT PRIMARY KEY,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL
);

CREATE TABLE sable_client_domain_seen (
    client_key TEXT NOT NULL,
    name_key TEXT NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    PRIMARY KEY (client_key, name_key)
);

CREATE INDEX sable_client_domain_seen_first_idx
ON sable_client_domain_seen (first_seen);

CREATE TABLE sable_client_identity (
    address TEXT NOT NULL,
    mac TEXT NOT NULL,
    source TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT '',
    kind_confidence INTEGER NOT NULL DEFAULT 0,
    kind_set BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    PRIMARY KEY (address, mac, source)
);

CREATE TABLE sable_unifi_network (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    gateway TEXT NOT NULL DEFAULT '',
    dhcp BOOLEAN NOT NULL DEFAULT FALSE,
    dhcp_dns TEXT NOT NULL DEFAULT '',
    read_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_unifi_station (
    mac TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    network_id TEXT NOT NULL DEFAULT '',
    addresses TEXT NOT NULL DEFAULT '',
    wired BOOLEAN NOT NULL DEFAULT FALSE,
    connected_at TIMESTAMP NOT NULL,
    last_seen TIMESTAMP,
    bytes BIGINT NOT NULL DEFAULT 0,
    read_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_unifi_station_traffic (
    mac TEXT NOT NULL,
    hour TIMESTAMP NOT NULL,
    connected_at TIMESTAMP NOT NULL,
    bytes BIGINT NOT NULL,
    read_at TIMESTAMP NOT NULL,
    PRIMARY KEY (mac, hour)
);

CREATE TABLE sable_insight_feedback (
    finding_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    until_at TIMESTAMP,
    label TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_insight_notified (
    target TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    notified_at TIMESTAMP NOT NULL,
    PRIMARY KEY (target, finding_id)
);

CREATE TABLE sable_push_subscriptions (
    endpoint TEXT PRIMARY KEY,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_user_profiles (
    user_id BIGINT PRIMARY KEY REFERENCES sable_users(id) ON DELETE CASCADE,
	display_name TEXT NOT NULL,
	email TEXT NOT NULL DEFAULT '',
	disabled BOOLEAN NOT NULL,
	password_login BOOLEAN NOT NULL DEFAULT TRUE,
	avatar_etag TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_user_avatars (
    user_id BIGINT PRIMARY KEY REFERENCES sable_users(id) ON DELETE CASCADE,
    content_type TEXT NOT NULL,
    image BLOB NOT NULL,
    source_url TEXT NOT NULL,
    etag TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    built_in BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_role_grants (
    role_id BIGINT NOT NULL REFERENCES sable_roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    surface TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (role_id, permission, surface, resource_type, resource_id)
);

CREATE TABLE sable_user_roles (
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES sable_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE sable_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX sable_sessions_expires_at_idx
ON sable_sessions (expires_at);

CREATE TABLE sable_api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP
);

CREATE TABLE sable_api_token_roles (
    token_id BIGINT NOT NULL REFERENCES sable_api_tokens(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES sable_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (token_id, role_id)
);

CREATE INDEX sable_api_tokens_expires_at_idx
ON sable_api_tokens (expires_at);

CREATE TABLE sable_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TIMESTAMP NOT NULL,
    user_id BIGINT REFERENCES sable_users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    details TEXT NOT NULL
);

CREATE INDEX sable_audit_log_occurred_at_idx
ON sable_audit_log (occurred_at);

CREATE TABLE sable_secrets (
    name TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_user_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    linked_at TIMESTAMP NOT NULL,
    last_login_at TIMESTAMP,
    PRIMARY KEY (provider, subject)
);

CREATE INDEX sable_user_identities_user_id_idx
ON sable_user_identities (user_id);

CREATE TABLE sable_passkeys (
 id TEXT PRIMARY KEY,
 user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
 data TEXT NOT NULL
);

CREATE INDEX sable_passkeys_user_idx ON sable_passkeys (user_id);

CREATE TABLE sable_dnssec_trust_points (
    owner TEXT PRIMARY KEY,
    initialized BOOLEAN NOT NULL,
    last_success TIMESTAMP NULL,
    next_refresh TIMESTAMP NULL,
    last_error TEXT NOT NULL,
    original_ttl_seconds BIGINT NOT NULL,
    signature_validity_seconds BIGINT NOT NULL
);

CREATE TABLE sable_dnssec_trust_anchors (
    owner TEXT NOT NULL,
    key_id TEXT NOT NULL,
    dnskey TEXT NOT NULL,
    state TEXT NOT NULL,
    first_seen TIMESTAMP NULL,
    hold_down_until TIMESTAMP NULL,
    last_seen TIMESTAMP NULL,
    revoked_at TIMESTAMP NULL,
    source_key_ids TEXT NOT NULL,
    PRIMARY KEY (owner, key_id)
);

CREATE TABLE sable_zones (
	id TEXT NOT NULL UNIQUE,
    name TEXT PRIMARY KEY,
    zone_type TEXT NOT NULL,
    default_ttl BIGINT NOT NULL,
    disabled BOOLEAN NOT NULL,
    zone_transfer TEXT NOT NULL,
    transfer_acl TEXT NOT NULL,
    notify_targets TEXT NOT NULL,
    primary_servers TEXT NOT NULL,
    primary_protocol TEXT NOT NULL,
    alias_zone TEXT NOT NULL DEFAULT '',
    catalog_zone TEXT NOT NULL DEFAULT '',
    catalog_group TEXT NOT NULL DEFAULT '',
    catalog_member_id TEXT NOT NULL DEFAULT '',
    catalog_change_owner TEXT NOT NULL DEFAULT '',
    tsig_key TEXT NOT NULL,
    dynamic_updates BOOLEAN NOT NULL,
    dnssec BOOLEAN NOT NULL,
    dnssec_algorithm TEXT NOT NULL,
    dnssec_denial TEXT NOT NULL,
    nsec3_iterations BIGINT NOT NULL,
    nsec3_salt TEXT NOT NULL,
    zsk_lifetime_ns BIGINT NOT NULL,
    ksk_lifetime_ns BIGINT NOT NULL,
    key_prepublish_ns BIGINT NOT NULL,
    key_retire_after_ns BIGINT NOT NULL,
    parent_ds_key_tag BIGINT NOT NULL,
    dnssec_validation_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE sable_zone_records (
    zone_name TEXT NOT NULL REFERENCES sable_zones(name) ON DELETE CASCADE,
    record_key TEXT NOT NULL,
    ordinal BIGINT NOT NULL,
    owner_name TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_value TEXT NOT NULL,
    ttl BIGINT NOT NULL,
    comments TEXT NOT NULL,
    disabled BOOLEAN NOT NULL,
    expires_at_ns BIGINT,
    source TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (zone_name, record_key)
);

CREATE INDEX sable_zone_records_lookup_idx
ON sable_zone_records (zone_name, owner_name, record_type);

CREATE TABLE sable_zone_revisions (
    zone_name TEXT NOT NULL,
    zone_id TEXT NOT NULL DEFAULT '',
    revision BIGINT NOT NULL,
    change_kind TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (zone_name, revision)
);

CREATE UNIQUE INDEX sable_zones_id_idx ON sable_zones (id);

CREATE INDEX sable_query_log_client_key_idx
ON sable_query_log (client_ip_key, id DESC);

CREATE INDEX sable_query_log_name_key_idx
ON sable_query_log (name_key, id DESC);

CREATE INDEX sable_query_log_rollup_bucket_idx
ON sable_query_log_rollup (bucket_start);

CREATE VIRTUAL TABLE sable_query_log_search USING fts5(
    domain, client, answers,
    content='', contentless_delete=1, tokenize='trigram'
);

CREATE UNIQUE INDEX sable_zone_records_key_idx
ON sable_zone_records (zone_name, record_key);
