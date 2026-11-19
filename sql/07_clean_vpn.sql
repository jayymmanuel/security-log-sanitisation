-- 07. VPN sessions -> clean.vpn_sessions

CREATE TEMP TABLE vpn_verdict AS
SELECT r.raw_id,
       clean.null_if_blank(r.session_id)                 AS session_id,
       clean.normalise_username(r.username)              AS username,
       clean.parse_inet(r.client_ip)                     AS client_ip,
       clean.map_value('country', r.country)             AS country,
       clean.parse_event_time(r.session_start)           AS session_start,
       clean.parse_event_time(r.session_end)             AS session_end,
       clean.null_if_blank(r.session_end)                AS session_end_text,
       clean.parse_bytes(r.bytes_in)                     AS bytes_in,
       clean.parse_bytes(r.bytes_out)                    AS bytes_out,
       row_number() OVER (PARTITION BY upper(clean.null_if_blank(r.session_id)) ORDER BY r.raw_id) AS copy_no
FROM raw.vpn_sessions r;

ALTER TABLE vpn_verdict ADD COLUMN reason text;
UPDATE vpn_verdict SET reason =
    CASE WHEN session_id IS NULL                                     THEN 'missing_session_id'
         WHEN copy_no > 1                                            THEN 'duplicate'
         WHEN username IS NULL                                       THEN 'missing_or_invalid_username'
         WHEN session_start IS NULL                                  THEN 'unparseable_start_time'
         WHEN session_end_text IS NOT NULL AND session_end IS NULL   THEN 'unparseable_end_time'
         -- End before start: one of the two timestamps is wrong, and nothing says which. Swapping them
         -- would invent data, so the row is quarantined instead.
         WHEN session_end < session_start                            THEN 'end_before_start'
         -- Country drives impossible-travel detection; a guessed country could raise or hide an alert.
         WHEN country IS NULL                                        THEN 'unmapped_country'
         WHEN client_ip IS NULL                                      THEN 'invalid_client_ip'
    END;

INSERT INTO quarantine.records (source, raw_id, reason, raw_record)
SELECT 'vpn_sessions', v.raw_id, v.reason, to_jsonb(r) - 'raw_id'
FROM vpn_verdict v JOIN raw.vpn_sessions r USING (raw_id)
WHERE v.reason IS NOT NULL;

CREATE TABLE clean.vpn_sessions (
    session_id    text PRIMARY KEY,
    username      text NOT NULL,
    employee_id   text REFERENCES clean.employees,
    client_ip     inet NOT NULL,
    country       char(2) NOT NULL,
    session_start timestamptz NOT NULL,
    session_end   timestamptz,                          -- NULL = still connected when the log was exported
    is_open       boolean NOT NULL,
    bytes_in      bigint CHECK (bytes_in >= 0),         -- NULL when the appliance logged a placeholder
    bytes_out     bigint CHECK (bytes_out >= 0),
    raw_id        bigint NOT NULL,
    CHECK (session_end IS NULL OR session_end >= session_start)
);

INSERT INTO clean.vpn_sessions
SELECT upper(v.session_id), v.username, e.employee_id, v.client_ip, v.country, v.session_start, v.session_end,
       v.session_end IS NULL, v.bytes_in, v.bytes_out, v.raw_id
FROM vpn_verdict v
LEFT JOIN clean.employees e ON e.username = v.username
WHERE v.reason IS NULL;
