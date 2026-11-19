-- 02. Load raw exports. Every column is TEXT: a typed column would reject or silently coerce bad values
-- on load, and we want to see every bad value. raw_id records the row's position in the file (lineage).
-- \copy paths are relative to where psql is started, so run the pipeline from the project root.

CREATE TABLE raw.hr_directory (
    raw_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    employee_id text, full_name text, email text, department text, employment_status text, leave_date text
);
\copy raw.hr_directory (employee_id, full_name, email, department, employment_status, leave_date) FROM 'data/raw/hr_directory.csv' WITH (FORMAT csv, HEADER true)

CREATE TABLE raw.auth_events (
    raw_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id text, source_system text, event_time text, username text, src_ip text, result text, logon_type text
);
\copy raw.auth_events (event_id, source_system, event_time, username, src_ip, result, logon_type) FROM 'data/raw/auth_events.csv' WITH (FORMAT csv, HEADER true)

CREATE TABLE raw.vpn_sessions (
    raw_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id text, username text, client_ip text, country text, session_start text, session_end text, bytes_in text, bytes_out text
);
\copy raw.vpn_sessions (session_id, username, client_ip, country, session_start, session_end, bytes_in, bytes_out) FROM 'data/raw/vpn_sessions.csv' WITH (FORMAT csv, HEADER true)

CREATE TABLE raw.firewall_logs (
    raw_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    log_time text, src_ip text, dst_ip text, dst_port text, protocol text, action text, bytes text
);
\copy raw.firewall_logs (log_time, src_ip, dst_ip, dst_port, protocol, action, bytes) FROM 'data/raw/firewall_logs.csv' WITH (FORMAT csv, HEADER true)

CREATE TABLE ref.planted_incidents (
    incident_type text, entity text, indicator text, incident_date date, description text
);
\copy ref.planted_incidents FROM 'data/ground_truth/planted_incidents.csv' WITH (FORMAT csv, HEADER true)

CREATE TABLE audit.raw_counts AS
SELECT 'hr_directory' AS source, count(*) AS raw_rows FROM raw.hr_directory
UNION ALL SELECT 'auth_events',   count(*) FROM raw.auth_events
UNION ALL SELECT 'vpn_sessions',  count(*) FROM raw.vpn_sessions
UNION ALL SELECT 'firewall_logs', count(*) FROM raw.firewall_logs;
