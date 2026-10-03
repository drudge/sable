-- The schema Sable 1.6.1 created on a new postgres database, taken from store.Open
-- at v1.6.1. migrate_test.go upgrades it.

CREATE TABLE sable_api_token_roles (
    token_id bigint NOT NULL,
    role_id bigint NOT NULL
);

CREATE TABLE sable_api_tokens (
    id bigint NOT NULL,
    token_hash text NOT NULL,
    user_id bigint NOT NULL,
    name text NOT NULL,
    created_at timestamp without time zone NOT NULL,
    expires_at timestamp without time zone,
    last_used_at timestamp without time zone
);

CREATE SEQUENCE sable_api_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE sable_api_tokens_id_seq OWNED BY sable_api_tokens.id;

CREATE TABLE sable_audit_log (
    id bigint NOT NULL,
    occurred_at timestamp without time zone NOT NULL,
    user_id bigint,
    action text NOT NULL,
    client_ip text NOT NULL,
    user_agent text NOT NULL,
    details text NOT NULL
);

CREATE SEQUENCE sable_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE sable_audit_log_id_seq OWNED BY sable_audit_log.id;

CREATE TABLE sable_client_domain_seen (
    client_key text NOT NULL,
    name_key text NOT NULL,
    first_seen timestamp without time zone NOT NULL,
    last_seen timestamp without time zone NOT NULL
);

CREATE TABLE sable_client_identity (
    address text NOT NULL,
    mac text NOT NULL,
    source text NOT NULL,
    hostname text DEFAULT ''::text NOT NULL,
    kind text DEFAULT ''::text NOT NULL,
    kind_confidence integer DEFAULT 0 NOT NULL,
    kind_set boolean DEFAULT false NOT NULL,
    first_seen timestamp without time zone NOT NULL,
    last_seen timestamp without time zone NOT NULL
);

CREATE TABLE sable_client_seen (
    client_key text NOT NULL,
    first_seen timestamp without time zone NOT NULL,
    last_seen timestamp without time zone NOT NULL
);

CREATE TABLE sable_dns_cache (
    request_wire bytea NOT NULL,
    response_wire bytea NOT NULL,
    stored_at timestamp without time zone NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    stale_until timestamp without time zone
);

CREATE TABLE sable_dnssec_trust_anchors (
    owner text NOT NULL,
    key_id text NOT NULL,
    dnskey text NOT NULL,
    state text NOT NULL,
    first_seen timestamp without time zone,
    hold_down_until timestamp without time zone,
    last_seen timestamp without time zone,
    revoked_at timestamp without time zone,
    source_key_ids text NOT NULL
);

CREATE TABLE sable_dnssec_trust_points (
    owner text NOT NULL,
    initialized boolean NOT NULL,
    last_success timestamp without time zone,
    next_refresh timestamp without time zone,
    last_error text NOT NULL,
    original_ttl_seconds bigint NOT NULL,
    signature_validity_seconds bigint NOT NULL
);

CREATE TABLE sable_insight_feedback (
    finding_id text NOT NULL,
    action text NOT NULL,
    until_at timestamp without time zone,
    label text DEFAULT ''::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_insight_notified (
    target text NOT NULL,
    finding_id text NOT NULL,
    notified_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_metadata (
    key text NOT NULL,
    value text NOT NULL
);

CREATE TABLE sable_passkeys (
    id text NOT NULL,
    user_id bigint NOT NULL,
    data text NOT NULL
);

CREATE TABLE sable_push_subscriptions (
    endpoint text NOT NULL,
    p256dh text NOT NULL,
    auth text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_query_log (
    id bigint NOT NULL,
    occurred_at timestamp without time zone NOT NULL,
    client_ip text NOT NULL,
    client_ip_key text DEFAULT ''::text NOT NULL,
    name text NOT NULL,
    name_key text DEFAULT ''::text NOT NULL,
    record_type integer NOT NULL,
    class integer NOT NULL,
    response_code integer NOT NULL,
    source text NOT NULL,
    protocol text DEFAULT ''::text NOT NULL,
    answer text DEFAULT ''::text NOT NULL,
    decision text DEFAULT '{}'::text NOT NULL,
    duration_us bigint NOT NULL
);

CREATE SEQUENCE sable_query_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE sable_query_log_id_seq OWNED BY sable_query_log.id;

CREATE TABLE sable_query_log_rollup (
    bucket_start timestamp without time zone NOT NULL,
    dimension text NOT NULL,
    value text NOT NULL,
    hits bigint NOT NULL
);

CREATE TABLE sable_query_log_rollup_day (
    dimension text NOT NULL,
    bucket_start timestamp without time zone NOT NULL,
    value text NOT NULL,
    hits bigint NOT NULL
);

CREATE TABLE sable_query_log_rollup_hour (
    dimension text NOT NULL,
    bucket_start timestamp without time zone NOT NULL,
    value text NOT NULL,
    hits bigint NOT NULL
);

CREATE TABLE sable_query_stats (
    bucket_start bigint NOT NULL,
    queries bigint DEFAULT 0 NOT NULL,
    no_error bigint DEFAULT 0 NOT NULL,
    server_failures bigint DEFAULT 0 NOT NULL,
    nx_domain bigint DEFAULT 0 NOT NULL,
    refused bigint DEFAULT 0 NOT NULL,
    blocked bigint DEFAULT 0 NOT NULL,
    cache_hits bigint DEFAULT 0 NOT NULL,
    cache_misses bigint DEFAULT 0 NOT NULL
);

CREATE TABLE sable_query_stats_totals (
    id integer NOT NULL,
    queries bigint DEFAULT 0 NOT NULL,
    no_error bigint DEFAULT 0 NOT NULL,
    server_failures bigint DEFAULT 0 NOT NULL,
    nx_domain bigint DEFAULT 0 NOT NULL,
    refused bigint DEFAULT 0 NOT NULL,
    blocked bigint DEFAULT 0 NOT NULL,
    failures bigint DEFAULT 0 NOT NULL,
    upstream_errors bigint DEFAULT 0 NOT NULL,
    cache_hits bigint DEFAULT 0 NOT NULL,
    cache_misses bigint DEFAULT 0 NOT NULL,
    routed_queries bigint DEFAULT 0 NOT NULL,
    local_answers bigint DEFAULT 0 NOT NULL,
    authoritative_answers bigint DEFAULT 0 NOT NULL,
    dnssec_secure bigint DEFAULT 0 NOT NULL,
    dnssec_insecure bigint DEFAULT 0 NOT NULL,
    dnssec_bogus bigint DEFAULT 0 NOT NULL
);

CREATE TABLE sable_role_grants (
    role_id bigint NOT NULL,
    permission text NOT NULL,
    surface text NOT NULL,
    resource_type text DEFAULT ''::text NOT NULL,
    resource_id text DEFAULT ''::text NOT NULL
);

CREATE TABLE sable_roles (
    id bigint NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    built_in boolean NOT NULL,
    created_at timestamp without time zone NOT NULL
);

CREATE SEQUENCE sable_roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE sable_roles_id_seq OWNED BY sable_roles.id;

CREATE TABLE sable_secrets (
    name text NOT NULL,
    ciphertext text NOT NULL,
    updated_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_server_log (
    id bigint NOT NULL,
    occurred_at timestamp without time zone NOT NULL,
    level integer NOT NULL,
    message text NOT NULL,
    attributes text DEFAULT ''::text NOT NULL
);

CREATE SEQUENCE sable_server_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE sable_server_log_id_seq OWNED BY sable_server_log.id;

CREATE TABLE sable_sessions (
    token_hash text NOT NULL,
    user_id bigint NOT NULL,
    csrf_token text NOT NULL,
    created_at timestamp without time zone NOT NULL,
    expires_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_unifi_network (
    id text NOT NULL,
    name text NOT NULL,
    gateway text DEFAULT ''::text NOT NULL,
    dhcp boolean DEFAULT false NOT NULL,
    dhcp_dns text DEFAULT ''::text NOT NULL,
    read_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_unifi_station (
    mac text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    network_id text DEFAULT ''::text NOT NULL,
    addresses text DEFAULT ''::text NOT NULL,
    wired boolean DEFAULT false NOT NULL,
    connected_at timestamp without time zone NOT NULL,
    last_seen timestamp without time zone,
    bytes bigint DEFAULT 0 NOT NULL,
    read_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_unifi_station_traffic (
    mac text NOT NULL,
    hour timestamp without time zone NOT NULL,
    connected_at timestamp without time zone NOT NULL,
    bytes bigint NOT NULL,
    read_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_user_avatars (
    user_id bigint NOT NULL,
    content_type text NOT NULL,
    image bytea NOT NULL,
    source_url text NOT NULL,
    etag text NOT NULL,
    updated_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_user_identities (
    provider text NOT NULL,
    subject text NOT NULL,
    user_id bigint NOT NULL,
    issuer text NOT NULL,
    linked_at timestamp without time zone NOT NULL,
    last_login_at timestamp without time zone
);

CREATE TABLE sable_user_profiles (
    user_id bigint NOT NULL,
    display_name text NOT NULL,
    email text DEFAULT ''::text NOT NULL,
    disabled boolean NOT NULL,
    password_login boolean DEFAULT true NOT NULL,
    avatar_etag text DEFAULT ''::text NOT NULL,
    updated_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_user_roles (
    user_id bigint NOT NULL,
    role_id bigint NOT NULL
);

CREATE TABLE sable_users (
    id bigint NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamp without time zone NOT NULL
);

CREATE SEQUENCE sable_users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE sable_users_id_seq OWNED BY sable_users.id;

CREATE TABLE sable_zone_records (
    zone_name text NOT NULL,
    record_key text NOT NULL,
    ordinal bigint NOT NULL,
    owner_name text NOT NULL,
    record_type text NOT NULL,
    record_value text NOT NULL,
    ttl bigint NOT NULL,
    comments text NOT NULL,
    disabled boolean NOT NULL,
    expires_at_ns bigint,
    source text DEFAULT ''::text NOT NULL
);

CREATE TABLE sable_zone_revisions (
    zone_name text NOT NULL,
    zone_id text DEFAULT ''::text NOT NULL,
    revision bigint NOT NULL,
    change_kind text NOT NULL,
    snapshot_json text NOT NULL,
    created_at timestamp without time zone NOT NULL
);

CREATE TABLE sable_zones (
    id text NOT NULL,
    name text NOT NULL,
    zone_type text NOT NULL,
    default_ttl bigint NOT NULL,
    disabled boolean NOT NULL,
    zone_transfer text NOT NULL,
    transfer_acl text NOT NULL,
    notify_targets text NOT NULL,
    primary_servers text NOT NULL,
    primary_protocol text NOT NULL,
    alias_zone text DEFAULT ''::text NOT NULL,
    catalog_zone text DEFAULT ''::text NOT NULL,
    catalog_group text DEFAULT ''::text NOT NULL,
    catalog_member_id text DEFAULT ''::text NOT NULL,
    catalog_change_owner text DEFAULT ''::text NOT NULL,
    tsig_key text NOT NULL,
    dynamic_updates boolean NOT NULL,
    dnssec boolean NOT NULL,
    dnssec_algorithm text NOT NULL,
    dnssec_denial text NOT NULL,
    nsec3_iterations bigint NOT NULL,
    nsec3_salt text NOT NULL,
    zsk_lifetime_ns bigint NOT NULL,
    ksk_lifetime_ns bigint NOT NULL,
    key_prepublish_ns bigint NOT NULL,
    key_retire_after_ns bigint NOT NULL,
    parent_ds_key_tag bigint NOT NULL,
    dnssec_validation_disabled boolean DEFAULT false NOT NULL,
    revision bigint NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);

ALTER TABLE ONLY sable_api_tokens ALTER COLUMN id SET DEFAULT nextval('sable_api_tokens_id_seq'::regclass);

ALTER TABLE ONLY sable_audit_log ALTER COLUMN id SET DEFAULT nextval('sable_audit_log_id_seq'::regclass);

ALTER TABLE ONLY sable_query_log ALTER COLUMN id SET DEFAULT nextval('sable_query_log_id_seq'::regclass);

ALTER TABLE ONLY sable_roles ALTER COLUMN id SET DEFAULT nextval('sable_roles_id_seq'::regclass);

ALTER TABLE ONLY sable_server_log ALTER COLUMN id SET DEFAULT nextval('sable_server_log_id_seq'::regclass);

ALTER TABLE ONLY sable_users ALTER COLUMN id SET DEFAULT nextval('sable_users_id_seq'::regclass);

ALTER TABLE ONLY sable_api_token_roles
    ADD CONSTRAINT sable_api_token_roles_pkey PRIMARY KEY (token_id, role_id);

ALTER TABLE ONLY sable_api_tokens
    ADD CONSTRAINT sable_api_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sable_api_tokens
    ADD CONSTRAINT sable_api_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY sable_audit_log
    ADD CONSTRAINT sable_audit_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sable_client_domain_seen
    ADD CONSTRAINT sable_client_domain_seen_pkey PRIMARY KEY (client_key, name_key);

ALTER TABLE ONLY sable_client_identity
    ADD CONSTRAINT sable_client_identity_pkey PRIMARY KEY (address, mac, source);

ALTER TABLE ONLY sable_client_seen
    ADD CONSTRAINT sable_client_seen_pkey PRIMARY KEY (client_key);

ALTER TABLE ONLY sable_dns_cache
    ADD CONSTRAINT sable_dns_cache_pkey PRIMARY KEY (request_wire);

ALTER TABLE ONLY sable_dnssec_trust_anchors
    ADD CONSTRAINT sable_dnssec_trust_anchors_pkey PRIMARY KEY (owner, key_id);

ALTER TABLE ONLY sable_dnssec_trust_points
    ADD CONSTRAINT sable_dnssec_trust_points_pkey PRIMARY KEY (owner);

ALTER TABLE ONLY sable_insight_feedback
    ADD CONSTRAINT sable_insight_feedback_pkey PRIMARY KEY (finding_id);

ALTER TABLE ONLY sable_insight_notified
    ADD CONSTRAINT sable_insight_notified_pkey PRIMARY KEY (target, finding_id);

ALTER TABLE ONLY sable_metadata
    ADD CONSTRAINT sable_metadata_pkey PRIMARY KEY (key);

ALTER TABLE ONLY sable_passkeys
    ADD CONSTRAINT sable_passkeys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sable_push_subscriptions
    ADD CONSTRAINT sable_push_subscriptions_pkey PRIMARY KEY (endpoint);

ALTER TABLE ONLY sable_query_log
    ADD CONSTRAINT sable_query_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sable_query_log_rollup_day
    ADD CONSTRAINT sable_query_log_rollup_day_pkey PRIMARY KEY (dimension, bucket_start, value);

ALTER TABLE ONLY sable_query_log_rollup_hour
    ADD CONSTRAINT sable_query_log_rollup_hour_pkey PRIMARY KEY (dimension, bucket_start, value);

ALTER TABLE ONLY sable_query_log_rollup
    ADD CONSTRAINT sable_query_log_rollup_pkey PRIMARY KEY (bucket_start, dimension, value);

ALTER TABLE ONLY sable_query_stats
    ADD CONSTRAINT sable_query_stats_pkey PRIMARY KEY (bucket_start);

ALTER TABLE ONLY sable_query_stats_totals
    ADD CONSTRAINT sable_query_stats_totals_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sable_role_grants
    ADD CONSTRAINT sable_role_grants_pkey PRIMARY KEY (role_id, permission, surface, resource_type, resource_id);

ALTER TABLE ONLY sable_roles
    ADD CONSTRAINT sable_roles_name_key UNIQUE (name);

ALTER TABLE ONLY sable_roles
    ADD CONSTRAINT sable_roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sable_secrets
    ADD CONSTRAINT sable_secrets_pkey PRIMARY KEY (name);

ALTER TABLE ONLY sable_server_log
    ADD CONSTRAINT sable_server_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sable_sessions
    ADD CONSTRAINT sable_sessions_pkey PRIMARY KEY (token_hash);

ALTER TABLE ONLY sable_unifi_network
    ADD CONSTRAINT sable_unifi_network_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sable_unifi_station
    ADD CONSTRAINT sable_unifi_station_pkey PRIMARY KEY (mac);

ALTER TABLE ONLY sable_unifi_station_traffic
    ADD CONSTRAINT sable_unifi_station_traffic_pkey PRIMARY KEY (mac, hour);

ALTER TABLE ONLY sable_user_avatars
    ADD CONSTRAINT sable_user_avatars_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY sable_user_identities
    ADD CONSTRAINT sable_user_identities_pkey PRIMARY KEY (provider, subject);

ALTER TABLE ONLY sable_user_profiles
    ADD CONSTRAINT sable_user_profiles_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY sable_user_roles
    ADD CONSTRAINT sable_user_roles_pkey PRIMARY KEY (user_id, role_id);

ALTER TABLE ONLY sable_users
    ADD CONSTRAINT sable_users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sable_users
    ADD CONSTRAINT sable_users_username_key UNIQUE (username);

ALTER TABLE ONLY sable_zone_records
    ADD CONSTRAINT sable_zone_records_pkey PRIMARY KEY (zone_name, record_key);

ALTER TABLE ONLY sable_zone_revisions
    ADD CONSTRAINT sable_zone_revisions_pkey PRIMARY KEY (zone_name, revision);

ALTER TABLE ONLY sable_zones
    ADD CONSTRAINT sable_zones_id_key UNIQUE (id);

ALTER TABLE ONLY sable_zones
    ADD CONSTRAINT sable_zones_pkey PRIMARY KEY (name);

CREATE INDEX sable_api_tokens_expires_at_idx ON sable_api_tokens USING btree (expires_at);

CREATE INDEX sable_audit_log_occurred_at_idx ON sable_audit_log USING btree (occurred_at);

CREATE INDEX sable_client_domain_seen_first_idx ON sable_client_domain_seen USING btree (first_seen);

CREATE INDEX sable_passkeys_user_idx ON sable_passkeys USING btree (user_id);

CREATE INDEX sable_query_log_client_key_idx ON sable_query_log USING btree (client_ip_key, id DESC);

CREATE INDEX sable_query_log_name_key_idx ON sable_query_log USING btree (name_key, id DESC);

CREATE INDEX sable_query_log_occurred_at_idx ON sable_query_log USING btree (occurred_at);

CREATE INDEX sable_query_log_rollup_bucket_idx ON sable_query_log_rollup USING btree (bucket_start);

CREATE INDEX sable_server_log_occurred_at_idx ON sable_server_log USING btree (occurred_at);

CREATE INDEX sable_sessions_expires_at_idx ON sable_sessions USING btree (expires_at);

CREATE INDEX sable_user_identities_user_id_idx ON sable_user_identities USING btree (user_id);

CREATE UNIQUE INDEX sable_zone_records_key_idx ON sable_zone_records USING btree (zone_name, record_key);

CREATE INDEX sable_zone_records_lookup_idx ON sable_zone_records USING btree (zone_name, owner_name, record_type);

CREATE UNIQUE INDEX sable_zones_id_idx ON sable_zones USING btree (id);

ALTER TABLE ONLY sable_api_token_roles
    ADD CONSTRAINT sable_api_token_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES sable_roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_api_token_roles
    ADD CONSTRAINT sable_api_token_roles_token_id_fkey FOREIGN KEY (token_id) REFERENCES sable_api_tokens(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_api_tokens
    ADD CONSTRAINT sable_api_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES sable_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_audit_log
    ADD CONSTRAINT sable_audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES sable_users(id) ON DELETE SET NULL;

ALTER TABLE ONLY sable_passkeys
    ADD CONSTRAINT sable_passkeys_user_id_fkey FOREIGN KEY (user_id) REFERENCES sable_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_role_grants
    ADD CONSTRAINT sable_role_grants_role_id_fkey FOREIGN KEY (role_id) REFERENCES sable_roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_sessions
    ADD CONSTRAINT sable_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES sable_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_user_avatars
    ADD CONSTRAINT sable_user_avatars_user_id_fkey FOREIGN KEY (user_id) REFERENCES sable_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_user_identities
    ADD CONSTRAINT sable_user_identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES sable_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_user_profiles
    ADD CONSTRAINT sable_user_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES sable_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_user_roles
    ADD CONSTRAINT sable_user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES sable_roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_user_roles
    ADD CONSTRAINT sable_user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES sable_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY sable_zone_records
    ADD CONSTRAINT sable_zone_records_zone_name_fkey FOREIGN KEY (zone_name) REFERENCES sable_zones(name) ON DELETE CASCADE;
