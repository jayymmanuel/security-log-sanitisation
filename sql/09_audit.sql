-- 09. Audit: prove nothing was lost, and measure how much the data changed.

-- Every raw row must end up in exactly one place: the clean table or quarantine.
CREATE VIEW audit.reconciliation AS
WITH clean_counts AS (
    SELECT 'hr_directory' AS source, count(*) AS clean_rows FROM clean.employees
    UNION ALL SELECT 'auth_events',   count(*) FROM clean.auth_events
    UNION ALL SELECT 'vpn_sessions',  count(*) FROM clean.vpn_sessions
    UNION ALL SELECT 'firewall_logs', count(*) FROM clean.firewall_events),
q AS (
    SELECT source,
           count(*) FILTER (WHERE reason = 'duplicate')  AS duplicates,
           count(*) FILTER (WHERE reason <> 'duplicate') AS quarantined
    FROM quarantine.records GROUP BY source)
SELECT r.source, r.raw_rows,
       coalesce(q.duplicates, 0)  AS duplicates,
       coalesce(q.quarantined, 0) AS quarantined,
       c.clean_rows,
       round(100.0 * c.clean_rows / r.raw_rows, 2) AS pct_clean,
       r.raw_rows = c.clean_rows + coalesce(q.duplicates, 0) + coalesce(q.quarantined, 0) AS balanced
FROM audit.raw_counts r
JOIN clean_counts c USING (source)
LEFT JOIN q USING (source);

CREATE VIEW audit.quarantine_summary AS
SELECT source, reason, count(*) AS row_count,
       (array_agg(raw_record ORDER BY raw_id))[1] AS example
FROM quarantine.records
GROUP BY source, reason;

-- Raw categorical values with no entry in ref.value_map. Expected to be empty; anything here is a new
-- spelling that needs a mapping decision.
CREATE VIEW audit.unmapped_values AS
WITH observed AS (
    SELECT 'auth_result' AS domain, result AS raw_value FROM raw.auth_events
    UNION SELECT 'logon_type',        logon_type        FROM raw.auth_events
    UNION SELECT 'source_system',     source_system     FROM raw.auth_events
    UNION SELECT 'employment_status', employment_status FROM raw.hr_directory
    UNION SELECT 'department',        department        FROM raw.hr_directory
    UNION SELECT 'country',           country           FROM raw.vpn_sessions
    UNION SELECT 'fw_action',         action            FROM raw.firewall_logs
    UNION SELECT 'protocol',          protocol          FROM raw.firewall_logs)
SELECT o.domain, o.raw_value
FROM observed o
WHERE clean.null_if_blank(o.raw_value) IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM ref.value_map m WHERE m.domain = o.domain AND m.raw_value = lower(btrim(o.raw_value)));

-- Before and after: distinct values per field. Fewer distinct values after cleaning = variants of the same
-- thing collapsed into one (e.g. 5 spellings of a username become 1).
CREATE VIEW audit.distinct_values AS
SELECT 'auth_events' AS source, 'username' AS field,
       (SELECT count(DISTINCT username) FROM raw.auth_events) AS raw_distinct,
       (SELECT count(DISTINCT username) FROM clean.auth_events) AS clean_distinct
UNION ALL SELECT 'auth_events', 'result',
       (SELECT count(DISTINCT result) FROM raw.auth_events), (SELECT count(DISTINCT result) FROM clean.auth_events)
UNION ALL SELECT 'auth_events', 'source_system',
       (SELECT count(DISTINCT source_system) FROM raw.auth_events), (SELECT count(DISTINCT source_system) FROM clean.auth_events)
UNION ALL SELECT 'auth_events', 'src_ip',
       (SELECT count(DISTINCT src_ip) FROM raw.auth_events), (SELECT count(DISTINCT src_ip) FROM clean.auth_events)
UNION ALL SELECT 'auth_events', 'logon_type',
       (SELECT count(DISTINCT logon_type) FROM raw.auth_events), (SELECT count(DISTINCT logon_type) FROM clean.auth_events)
UNION ALL SELECT 'hr_directory', 'department',
       (SELECT count(DISTINCT department) FROM raw.hr_directory), (SELECT count(DISTINCT department) FROM clean.employees)
UNION ALL SELECT 'hr_directory', 'employment_status',
       (SELECT count(DISTINCT employment_status) FROM raw.hr_directory), (SELECT count(DISTINCT status) FROM clean.employees)
UNION ALL SELECT 'vpn_sessions', 'country',
       (SELECT count(DISTINCT country) FROM raw.vpn_sessions), (SELECT count(DISTINCT country) FROM clean.vpn_sessions)
UNION ALL SELECT 'firewall_logs', 'dst_port',
       (SELECT count(DISTINCT dst_port) FROM raw.firewall_logs), (SELECT count(DISTINCT dst_port) FROM clean.firewall_events)
UNION ALL SELECT 'firewall_logs', 'action',
       (SELECT count(DISTINCT action) FROM raw.firewall_logs), (SELECT count(DISTINCT action) FROM clean.firewall_events);
