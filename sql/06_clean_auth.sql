-- 06. Sign-in events -> clean.auth_events
-- Three systems (two domain controllers and Entra ID) export the same kind of event in different formats.

CREATE TEMP TABLE auth_staged AS
SELECT r.raw_id,
       clean.null_if_blank(r.event_id)                   AS event_id,
       clean.map_value('source_system', r.source_system) AS source_system,
       clean.parse_event_time(r.event_time)              AS event_time,
       clean.null_if_blank(r.event_time)                 AS event_time_text,
       clean.normalise_username(r.username)              AS username,
       clean.parse_inet(r.src_ip)                        AS src_ip,
       clean.null_if_blank(r.src_ip)                     AS src_ip_text,
       clean.map_value('auth_result', r.result)          AS result,
       clean.map_value('logon_type', r.logon_type)       AS logon_type
FROM raw.auth_events r;

-- Duplicates: the same event exported twice. Matched on the cleaned source and event ID, so copies that
-- differ only in whitespace or case ("DC01" vs " dc01") are still recognised as the same event.
CREATE TEMP TABLE auth_verdict AS
SELECT s.*,
       row_number() OVER (PARTITION BY coalesce(source_system, 'UNMAPPED'), event_id ORDER BY raw_id) AS copy_no
FROM auth_staged s;

ALTER TABLE auth_verdict ADD COLUMN reason text;
UPDATE auth_verdict SET reason =
    CASE WHEN event_id IS NULL                                        THEN 'missing_event_id'
         WHEN copy_no > 1                                             THEN 'duplicate'
         WHEN source_system IS NULL                                   THEN 'unmapped_source_system'
         WHEN event_time IS NULL                                      THEN 'unparseable_time'
         WHEN event_time > ref.setting('extract_time')::timestamptz   THEN 'future_time_clock_skew'
         WHEN event_time < ref.setting('period_start')::timestamptz   THEN 'before_period'
         WHEN username IS NULL                                        THEN 'missing_or_invalid_username'
         WHEN result IS NULL                                          THEN 'unmapped_result'
    END;

INSERT INTO quarantine.records (source, raw_id, reason, raw_record)
SELECT 'auth_events', v.raw_id, v.reason, to_jsonb(r) - 'raw_id'
FROM auth_verdict v JOIN raw.auth_events r USING (raw_id)
WHERE v.reason IS NOT NULL;

-- Deliberately NOT quarantined:
--   * an unknown username: attackers try accounts that don't exist (admin, test). Dropping them would hide
--     a password spray, so they are kept and labelled 'unknown_account'.
--   * a missing or invalid source IP: the sign-in still happened. The IP is set to NULL and ip_issue says why.
CREATE TABLE clean.auth_events (
    event_key      text PRIMARY KEY,                    -- source system + event ID, unique across systems
    source_system  text NOT NULL,
    event_time     timestamptz NOT NULL,
    username       text NOT NULL CHECK (username ~ '^[a-z0-9._-]+$'),
    employee_id    text REFERENCES clean.employees,
    account_status text NOT NULL CHECK (account_status IN ('active', 'leaver', 'unknown_account')),
    src_ip         inet,
    ip_issue       text CHECK (ip_issue IN ('missing', 'invalid')),
    result         text NOT NULL CHECK (result IN ('success', 'failure')),
    logon_type     text,
    raw_id         bigint NOT NULL
);

INSERT INTO clean.auth_events
SELECT v.source_system || ':' || v.event_id,
       v.source_system, v.event_time, v.username,
       e.employee_id,
       coalesce(e.status, 'unknown_account'),
       v.src_ip,
       CASE WHEN v.src_ip_text IS NULL THEN 'missing' WHEN v.src_ip IS NULL THEN 'invalid' END,
       v.result, v.logon_type, v.raw_id
FROM auth_verdict v
LEFT JOIN clean.employees e ON e.username = v.username
WHERE v.reason IS NULL;

CREATE INDEX ON clean.auth_events (username, event_time);
CREATE INDEX ON clean.auth_events (src_ip, event_time);
