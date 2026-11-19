-- 11. Automated tests. Each test is a SQL check recorded as pass or fail. If any test fails, the final
-- block raises an error, so the run (and the GitHub Actions build) stops with a non-zero exit code.

CREATE TEMP TABLE test_results (test_name text, passed boolean, detail text);

-- Completeness: nothing lost, nothing double counted --------------------------------------------------
INSERT INTO test_results
SELECT 'Every raw row is either clean or quarantined', bool_and(balanced),
       string_agg(source || ' ' || raw_rows || ' = ' || clean_rows || ' + ' || duplicates || ' + ' || quarantined, '; ')
FROM audit.reconciliation;

INSERT INTO test_results
SELECT 'No row is both clean and quarantined', count(*) = 0, count(*) || ' overlapping rows'
FROM quarantine.records q
WHERE (q.source = 'auth_events'   AND EXISTS (SELECT 1 FROM clean.auth_events c     WHERE c.raw_id = q.raw_id))
   OR (q.source = 'vpn_sessions'  AND EXISTS (SELECT 1 FROM clean.vpn_sessions c    WHERE c.raw_id = q.raw_id))
   OR (q.source = 'firewall_logs' AND EXISTS (SELECT 1 FROM clean.firewall_events c WHERE c.raw_id = q.raw_id))
   OR (q.source = 'hr_directory'  AND EXISTS (SELECT 1 FROM clean.employees c       WHERE c.raw_id = q.raw_id));

INSERT INTO test_results
SELECT 'Every categorical value has a mapping', count(*) = 0,
       coalesce(string_agg(domain || ': ' || raw_value, ', '), 'none unmapped')
FROM audit.unmapped_values;

-- Validity: clean values are in standard form -----------------------------------------------------------
INSERT INTO test_results
SELECT 'Sign-in times fall inside the reporting period', count(*) = 0, count(*) || ' out of range'
FROM clean.auth_events
WHERE event_time < ref.setting('period_start')::timestamptz OR event_time > ref.setting('extract_time')::timestamptz;

INSERT INTO test_results
SELECT 'Usernames carry no domain, case or whitespace variants', count(*) = 0, count(*) || ' non-canonical'
FROM (SELECT username FROM clean.auth_events UNION ALL SELECT username FROM clean.vpn_sessions) u
WHERE username <> lower(btrim(username)) OR username LIKE '%\%' OR username LIKE '%@%';

INSERT INTO test_results
SELECT 'Each sign-in event appears once', count(*) = count(DISTINCT (source_system, split_part(event_key, ':', 2))),
       count(*) || ' rows'
FROM clean.auth_events;

INSERT INTO test_results
SELECT 'IP flag is set exactly when the IP is missing', count(*) = 0, count(*) || ' inconsistent rows'
FROM clean.auth_events WHERE (src_ip IS NULL) <> (ip_issue IS NOT NULL);

INSERT INTO test_results
SELECT 'VPN sessions end after they start and use ISO country codes', count(*) = 0, count(*) || ' bad rows'
FROM clean.vpn_sessions
WHERE session_end < session_start OR country !~ '^[A-Z]{2}$';

INSERT INTO test_results
SELECT 'Firewall ports are valid and directions match address ranges', count(*) = 0, count(*) || ' bad rows'
FROM clean.firewall_events
WHERE dst_port NOT BETWEEN 0 AND 65535
   OR (direction = 'outbound' AND NOT (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' OR src_ip << '192.168.0.0/16'));

INSERT INTO test_results
SELECT 'Every leaver has a leave date', count(*) = 0, count(*) || ' leavers without a date'
FROM clean.employees WHERE status = 'leaver' AND leave_date IS NULL;

-- Parsing rules behave correctly at the known edge cases -----------------------------------------------
INSERT INTO test_results
SELECT 'UK local times convert to UTC either side of the clock change',
       clean.parse_event_time('24/10/2026 12:00:00') = '2026-10-24 11:00:00+00'::timestamptz   -- BST, UTC+1
   AND clean.parse_event_time('25/10/2026 12:00:00') = '2026-10-25 12:00:00+00'::timestamptz,  -- GMT, UTC+0
       '24 Oct is BST (UTC+1), 25 Oct is GMT (UTC+0)';

SET datestyle = 'ISO, MDY';
INSERT INTO test_results
SELECT 'UK dates parse the same on a US-configured server',
       clean.parse_uk_date('11/10/2026') = date '2026-10-11', 'DateStyle MDY would read 11/10 as 10 November';
RESET datestyle;

INSERT INTO test_results
SELECT 'Impossible calendar dates are rejected, not rolled over',
       clean.parse_event_time('31/02/2026 10:00:00') IS NULL, '31 February must not become 3 March';

INSERT INTO test_results
SELECT 'Zero-padded and IPv4-mapped addresses normalise; impossible ones are rejected',
       clean.parse_inet('010.001.004.022') = '10.1.4.22'::inet
   AND clean.parse_inet('::ffff:10.1.4.22') = '10.1.4.22'::inet
   AND clean.parse_inet('10.1.4.300') IS NULL, '010.001.004.022 and ::ffff:10.1.4.22 -> 10.1.4.22; 10.1.4.300 -> NULL';

-- Outcome: detections on clean data find every planted incident, and nothing else ----------------------
INSERT INTO test_results
SELECT 'Every planted incident is detected on clean data', bool_and(found_on_clean_data),
       count(*) FILTER (WHERE found_on_clean_data) || ' of ' || count(*) || ' found'
FROM detect.scorecard;

INSERT INTO test_results
SELECT 'Clean detections raise no alerts beyond the planted incidents',
       (SELECT count(*) FROM detect.brute_force)       = 1
   AND (SELECT count(*) FROM detect.password_spray)    = 1
   AND (SELECT count(*) FROM detect.leaver_sign_ins)   = 3
   AND (SELECT count(*) FROM detect.impossible_travel) = 1
   AND (SELECT count(*) FROM detect.beaconing)         = 1,
       'expected 1 brute force, 1 spray, 3 leavers, 1 travel, 1 beacon';

\echo
\echo '==== Test results ===='
SELECT CASE WHEN passed THEN 'PASS' ELSE 'FAIL' END AS result, test_name, detail FROM test_results;

DO $$
DECLARE n int;
BEGIN
    SELECT count(*) INTO n FROM test_results WHERE NOT passed;
    IF n > 0 THEN
        RAISE EXCEPTION '% test(s) failed: see FAIL rows above', n;
    END IF;
END $$;
\echo 'All tests passed.'
