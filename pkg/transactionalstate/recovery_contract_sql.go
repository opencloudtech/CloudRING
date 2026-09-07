// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package transactionalstate

const recoveryContractQuery = `WITH roles AS (
  SELECT '{{owner}}'::text AS owner_name, '{{application}}'::text AS app_name,
    (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = '{{owner}}') AS owner_oid,
    (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = '{{application}}') AS app_oid
), relations AS (
  SELECT c.*, n.nspowner, n.nspacl FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'cloudring_state' AND c.relkind NOT IN ('i', 'I')
), privilege_names AS (
  SELECT name, ordinal FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN']) WITH ORDINALITY AS p(name, ordinal)
), table_acl AS (
  SELECT a.* FROM relations c, LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) a
), schema_acl AS (
  SELECT a.* FROM pg_catalog.pg_namespace n, LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) a
  WHERE n.nspname = 'cloudring_state'
)
SELECT pg_catalog.jsonb_build_object(
  'schemaVersion', '{{schema}}',
  'roles', pg_catalog.jsonb_build_object('owner', r.owner_name, 'application', r.app_name),
  'database', current_database(),
  'databaseOwner', (SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_catalog.pg_database WHERE datname = current_database()),
  'schemaOwner', (SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname = 'cloudring_state'),
  'applicationRole', (SELECT pg_catalog.jsonb_build_object(
    'name', p.rolname, 'superuser', p.rolsuper, 'inherit', p.rolinherit, 'createRole', p.rolcreaterole,
    'createDatabase', p.rolcreatedb, 'login', p.rolcanlogin, 'replication', p.rolreplication, 'bypassRls', p.rolbypassrls,
    'membershipCount', (SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member = p.oid)
  ) FROM pg_catalog.pg_roles p WHERE p.oid = r.app_oid),
  'relations', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'name', c.relname, 'owner', pg_catalog.pg_get_userbyid(c.relowner), 'kind', c.relkind::text,
    'persistence', c.relpersistence::text, 'rowSecurity', c.relrowsecurity, 'forceRowSecurity', c.relforcerowsecurity,
    'inherited', EXISTS (SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid = c.oid OR inhparent = c.oid)
  ) ORDER BY c.relname COLLATE "C") FROM relations c), '[]'::jsonb),
  'columns', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'table', c.relname, 'name', a.attname, 'dataType', pg_catalog.format_type(a.atttypid, a.atttypmod),
    'notNull', a.attnotnull, 'default', COALESCE(pg_catalog.pg_get_expr(ad.adbin, ad.adrelid), ''),
    'collation', COALESCE(coll.collname, ''), 'identity', a.attidentity::text, 'generated', a.attgenerated::text
  ) ORDER BY c.relname COLLATE "C", a.attnum)
  FROM relations c JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
  LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = c.oid AND ad.adnum = a.attnum
  LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = a.attcollation WHERE c.relkind = 'r'), '[]'::jsonb),
  'constraints', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'table', c.relname, 'name', con.conname, 'type', con.contype::text,
    'definition', pg_catalog.pg_get_constraintdef(con.oid, false), 'validated', con.convalidated,
    'deferrable', con.condeferrable, 'initiallyDeferred', con.condeferred
  ) ORDER BY c.relname COLLATE "C", con.conname COLLATE "C")
  FROM relations c JOIN pg_catalog.pg_constraint con ON con.conrelid = c.oid WHERE con.contype != 'n'), '[]'::jsonb),
  'indexes', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'table', t.relname, 'name', c.relname, 'owner', pg_catalog.pg_get_userbyid(c.relowner),
    'kind', c.relkind::text, 'persistence', c.relpersistence::text,
    'definition', pg_catalog.pg_get_indexdef(c.oid, 0, false),
    'unique', i.indisunique, 'primary', i.indisprimary, 'exclusion', i.indisexclusion,
    'immediate', i.indimmediate, 'valid', i.indisvalid, 'ready', i.indisready, 'live', i.indislive,
    'nullsNotDistinct', i.indnullsnotdistinct,
    'constraintName', COALESCE(con.conname, ''), 'constraintType', COALESCE(con.contype::text, '')
  ) ORDER BY t.relname COLLATE "C", c.relname COLLATE "C")
  FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_catalog.pg_index i ON i.indexrelid = c.oid
  LEFT JOIN pg_catalog.pg_class t ON t.oid = i.indrelid
  LEFT JOIN pg_catalog.pg_constraint con ON con.conindid = c.oid AND con.conrelid = i.indrelid AND con.contype IN ('p', 'u', 'x')
  WHERE n.nspname = 'cloudring_state' AND c.relkind IN ('i', 'I')), '[]'::jsonb),
  'migrations', COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('version', version, 'checksum', checksum) ORDER BY version) FROM cloudring_state.schema_migrations), '[]'::jsonb),
  'privileges', pg_catalog.jsonb_build_object(
    'databaseConnect', pg_catalog.has_database_privilege(r.app_oid, current_database(), 'CONNECT'),
    'databaseCreate', pg_catalog.has_database_privilege(r.app_oid, current_database(), 'CREATE'),
    'databaseTemporary', pg_catalog.has_database_privilege(r.app_oid, current_database(), 'TEMPORARY'),
    'schemaUsage', pg_catalog.has_schema_privilege(r.app_oid, 'cloudring_state', 'USAGE'),
    'schemaCreate', pg_catalog.has_schema_privilege(r.app_oid, 'cloudring_state', 'CREATE'),
    'documents', COALESCE((SELECT pg_catalog.jsonb_agg(name ORDER BY ordinal) FROM privilege_names WHERE pg_catalog.has_table_privilege(r.app_oid, 'cloudring_state.documents', name)), '[]'::jsonb),
    'auditJournal', COALESCE((SELECT pg_catalog.jsonb_agg(name ORDER BY ordinal) FROM privilege_names WHERE pg_catalog.has_table_privilege(r.app_oid, 'cloudring_state.audit_journal', name)), '[]'::jsonb),
    'schemaMigrations', COALESCE((SELECT pg_catalog.jsonb_agg(name ORDER BY ordinal) FROM privilege_names WHERE pg_catalog.has_table_privilege(r.app_oid, 'cloudring_state.schema_migrations', name)), '[]'::jsonb)
  ),
  'unexpectedAclCount', (SELECT count(*) FROM (SELECT * FROM table_acl UNION ALL SELECT * FROM schema_acl) a WHERE a.grantee NOT IN (r.owner_oid, r.app_oid) OR (a.grantee = r.app_oid AND a.is_grantable)),
  'columnAclCount', (SELECT count(*) FROM relations c JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid WHERE a.attnum > 0 AND NOT a.attisdropped AND cardinality(a.attacl) > 0),
  'functionCount', (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'cloudring_state'),
  'userTriggerCount', (SELECT count(*) FROM relations c JOIN pg_catalog.pg_trigger t ON t.tgrelid = c.oid WHERE NOT t.tgisinternal),
  'ruleCount', (SELECT count(*) FROM relations c JOIN pg_catalog.pg_rewrite rw ON rw.ev_class = c.oid),
  'policyCount', (SELECT count(*) FROM relations c JOIN pg_catalog.pg_policy p ON p.polrelid = c.oid)
)::text FROM roles r;`
