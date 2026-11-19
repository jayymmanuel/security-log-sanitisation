-- 10. Security detections.
-- Each detection runs twice:
--   detect.<name>         on the sanitised clean.* tables
--   detect.naive_<name>   on raw.* as exported, the way an analyst would query it without cleaning.
-- The naive versions are given parsed timestamps for free (otherwise no time logic is possible at all).
-- Everything else is used as exported, filtering on the values that appear at the top of each file.

----------------------------------------------------------------------------- 1. Brute force
-- 10+ failed sign-ins for one account from one IP within 15 minutes.
CREATE VIEW detect.brute_force AS
WITH f AS (
    SELECT username, src_ip, event_time,
           count(*) OVER (PARTITION BY username, src_ip ORDER BY event_time
                          RANGE BETWEEN interval '15 minutes' PRECEDING AND CURRENT ROW) AS fails_15m
    FROM clean.auth_events
    WHERE result = 'failure' AND src_ip IS NOT NULL),
g AS (
    SELECT username, src_ip, count(*) AS total_failures, max(fails_15m) AS peak_failures_15m,
           min(event_time) AS first_failure, max(event_time) AS last_failure
    FROM f GROUP BY username, src_ip
    HAVING max(fails_15m) >= 10)
SELECT g.*,
       EXISTS (SELECT 1 FROM clean.auth_events s
               WHERE s.username = g.username AND s.src_ip = g.src_ip AND s.result = 'success'
                 AND s.event_time BETWEEN g.last_failure AND g.last_failure + interval '30 minutes') AS followed_by_success
FROM g;

CREATE VIEW detect.naive_brute_force AS
SELECT username, src_ip, count(*) AS failures
FROM raw.auth_events
WHERE result IN ('4625', 'Failure')
GROUP BY username, src_ip
HAVING count(*) >= 10;                                 -- whole month, no time window: more generous than the clean rule

----------------------------------------------------------------------------- 2. Password spray
-- One IP failing against 15+ different accounts within 30 minutes.
CREATE VIEW detect.password_spray AS
WITH f AS (
    SELECT src_ip, username, account_status, event_time
    FROM clean.auth_events WHERE result = 'failure' AND src_ip IS NOT NULL),
w AS (
    SELECT a.src_ip, a.event_time AS window_start,
           count(DISTINCT b.username) AS accounts_30m,
           count(DISTINCT b.username) FILTER (WHERE b.account_status = 'unknown_account') AS unknown_accounts_30m
    FROM f a
    JOIN f b ON b.src_ip = a.src_ip AND b.event_time >= a.event_time AND b.event_time < a.event_time + interval '30 minutes'
    GROUP BY a.src_ip, a.event_time)
SELECT src_ip, max(accounts_30m) AS peak_accounts_30m, max(unknown_accounts_30m) AS unknown_accounts_targeted,
       min(window_start) AS first_seen
FROM w WHERE accounts_30m >= 15
GROUP BY src_ip;

CREATE VIEW detect.naive_password_spray AS
SELECT src_ip, count(DISTINCT username) AS accounts
FROM raw.auth_events
WHERE result IN ('4625', 'Failure')
GROUP BY src_ip
HAVING count(DISTINCT username) >= 15;

----------------------------------------------------------------------------- 3. Leaver sign-ins
-- Successful sign-ins after the person's leave date (compared as UK calendar days).
CREATE VIEW detect.leaver_sign_ins AS
SELECT a.username, e.employee_id, e.full_name, e.leave_date,
       count(*) AS sign_ins_after_leaving,
       min(a.event_time) AS first_after, max(a.event_time) AS last_after
FROM clean.auth_events a
JOIN clean.employees e USING (employee_id)
WHERE e.status = 'leaver' AND a.result = 'success'
  AND (a.event_time AT TIME ZONE 'Europe/London')::date > e.leave_date
GROUP BY a.username, e.employee_id, e.full_name, e.leave_date;

-- Naive: join usernames to HR emails exactly, trust the 'Leaver' label, and read dd/mm/yyyy dates the way
-- a server with DateStyle MDY does (to_date with MM/DD reproduces that; a plain ::date cast would also fail
-- outright on dates like 24/10/2026).
CREATE VIEW detect.naive_leaver_sign_ins AS
SELECT a.username, h.leave_date AS leave_date_text, to_date(h.leave_date, 'MM/DD/YYYY') AS leave_date_as_read,
       count(*) AS sign_ins_after_leaving
FROM raw.auth_events a
JOIN raw.hr_directory h ON a.username = h.email
WHERE h.employment_status = 'Leaver' AND a.result IN ('4624', 'Success')
  AND h.leave_date ~ '^\d{2}/\d{2}/\d{4}$'
  AND clean.parse_event_time(a.event_time)::date > to_date(h.leave_date, 'MM/DD/YYYY')
GROUP BY a.username, h.leave_date;

----------------------------------------------------------------------------- 4. Impossible travel
-- Consecutive VPN sessions for one user from different countries less than 2 hours apart.
CREATE VIEW detect.impossible_travel AS
WITH s AS (
    SELECT username, session_id, client_ip, country, session_start, session_end,
           lag(country)       OVER w AS prev_country,
           lag(session_id)    OVER w AS prev_session_id,
           coalesce(lag(session_end) OVER w, lag(session_start) OVER w) AS prev_end
    FROM clean.vpn_sessions
    WINDOW w AS (PARTITION BY username ORDER BY session_start))
SELECT username, prev_session_id, prev_country, prev_end, session_id, country, session_start, client_ip,
       round(extract(epoch FROM session_start - prev_end) / 60) AS minutes_between
FROM s
WHERE country <> prev_country AND session_start - prev_end < interval '2 hours';

CREATE VIEW detect.naive_impossible_travel AS
WITH s AS (
    SELECT username, country, clean.parse_event_time(session_start) AS session_start,
           lag(country) OVER w AS prev_country,
           lag(clean.parse_event_time(session_end)) OVER w AS prev_end
    FROM raw.vpn_sessions
    WINDOW w AS (PARTITION BY username ORDER BY clean.parse_event_time(session_start)))
SELECT * FROM s
WHERE country <> prev_country AND session_start - prev_end < interval '2 hours';

-- A common companion check: users seen connecting from more than one country.
CREATE VIEW detect.multi_country_users AS
SELECT username, array_agg(DISTINCT country ORDER BY country) AS countries
FROM clean.vpn_sessions GROUP BY username HAVING count(DISTINCT country) > 1;

CREATE VIEW detect.naive_multi_country_users AS
SELECT username, array_agg(DISTINCT country ORDER BY country) AS countries
FROM raw.vpn_sessions GROUP BY username HAVING count(DISTINCT country) > 1;

----------------------------------------------------------------------------- 5. Beaconing
-- Malware "phones home" on a fixed timer. Signal: many allowed outbound connections from one host to one
-- destination and port, with very regular gaps (coefficient of variation = stddev / mean below 0.25).
CREATE VIEW detect.beaconing AS
WITH c AS (
    SELECT src_ip, dst_ip, dst_port, log_time,
           extract(epoch FROM log_time - lag(log_time) OVER (PARTITION BY src_ip, dst_ip, dst_port ORDER BY log_time)) AS gap_s
    FROM clean.firewall_events
    WHERE direction = 'outbound' AND action = 'allow')
SELECT src_ip, dst_ip, dst_port, count(*) AS connections,
       min(log_time) AS first_seen, max(log_time) AS last_seen,
       round(avg(gap_s)::numeric, 1) AS mean_gap_s,
       round((stddev_samp(gap_s) / avg(gap_s))::numeric, 3) AS gap_variation
FROM c
GROUP BY src_ip, dst_ip, dst_port
HAVING count(*) >= 50 AND stddev_samp(gap_s) / avg(gap_s) < 0.25;

CREATE VIEW detect.naive_beaconing AS
WITH c AS (
    SELECT src_ip, dst_ip, dst_port, clean.parse_event_time(log_time) AS t
    FROM raw.firewall_logs
    WHERE action = 'ALLOW'),
g AS (
    SELECT src_ip, dst_ip, dst_port, extract(epoch FROM t - lag(t) OVER (PARTITION BY src_ip, dst_ip, dst_port ORDER BY t)) AS gap_s
    FROM c)
SELECT src_ip, dst_ip, dst_port, count(*) AS connections,
       round((stddev_samp(gap_s) / avg(gap_s))::numeric, 3) AS gap_variation
FROM g
GROUP BY src_ip, dst_ip, dst_port
HAVING count(*) >= 50 AND stddev_samp(gap_s) / avg(gap_s) < 0.25;

----------------------------------------------------------------------------- Scorecard
-- Did each approach find each planted incident? Matched on the incident's key indicator.
CREATE VIEW detect.scorecard AS
SELECT p.incident_type, p.entity, p.indicator, p.incident_date,
       CASE p.incident_type
         WHEN 'brute_force'       THEN EXISTS (SELECT 1 FROM detect.naive_brute_force d WHERE clean.parse_inet(d.src_ip) = p.indicator::inet)
         WHEN 'password_spray'    THEN EXISTS (SELECT 1 FROM detect.naive_password_spray d WHERE clean.parse_inet(d.src_ip) = p.indicator::inet)
         WHEN 'leaver_sign_in'    THEN EXISTS (SELECT 1 FROM detect.naive_leaver_sign_ins d WHERE clean.normalise_username(d.username) = p.entity)
         WHEN 'impossible_travel' THEN EXISTS (SELECT 1 FROM detect.naive_impossible_travel d WHERE clean.normalise_username(d.username) = p.entity)
         WHEN 'beaconing'         THEN EXISTS (SELECT 1 FROM detect.naive_beaconing d WHERE clean.parse_inet(d.dst_ip) = p.indicator::inet)
       END AS found_on_raw_data,
       CASE p.incident_type
         WHEN 'brute_force'       THEN EXISTS (SELECT 1 FROM detect.brute_force d WHERE d.src_ip = p.indicator::inet AND d.username = p.entity)
         WHEN 'password_spray'    THEN EXISTS (SELECT 1 FROM detect.password_spray d WHERE d.src_ip = p.indicator::inet)
         WHEN 'leaver_sign_in'    THEN EXISTS (SELECT 1 FROM detect.leaver_sign_ins d WHERE d.username = p.entity)
         WHEN 'impossible_travel' THEN EXISTS (SELECT 1 FROM detect.impossible_travel d WHERE d.username = p.entity)
         WHEN 'beaconing'         THEN EXISTS (SELECT 1 FROM detect.beaconing d WHERE d.dst_ip = p.indicator::inet AND d.src_ip = p.entity::inet)
       END AS found_on_clean_data
FROM ref.planted_incidents p;

-- Alert volume: how many alerts each approach raises in total. Alerts that match no planted incident are
-- noise an analyst would have to triage.
CREATE VIEW detect.alert_volume AS
SELECT 'brute_force' AS detection,
       (SELECT count(*) FROM detect.naive_brute_force) AS raw_alerts, (SELECT count(*) FROM detect.brute_force) AS clean_alerts
UNION ALL SELECT 'password_spray',     (SELECT count(*) FROM detect.naive_password_spray),     (SELECT count(*) FROM detect.password_spray)
UNION ALL SELECT 'leaver_sign_ins',    (SELECT count(*) FROM detect.naive_leaver_sign_ins),    (SELECT count(*) FROM detect.leaver_sign_ins)
UNION ALL SELECT 'impossible_travel',  (SELECT count(*) FROM detect.naive_impossible_travel),  (SELECT count(*) FROM detect.impossible_travel)
UNION ALL SELECT 'multi_country_users',(SELECT count(*) FROM detect.naive_multi_country_users),(SELECT count(*) FROM detect.multi_country_users)
UNION ALL SELECT 'beaconing',          (SELECT count(*) FROM detect.naive_beaconing),          (SELECT count(*) FROM detect.beaconing);
