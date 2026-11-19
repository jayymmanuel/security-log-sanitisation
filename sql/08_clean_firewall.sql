-- 08. Firewall connection log -> clean.firewall_events

CREATE TEMP TABLE fw_staged AS
SELECT r.raw_id,
       clean.parse_event_time(r.log_time, ref.setting('syslog_year')::int) AS log_time,
       clean.parse_inet(r.src_ip)                AS src_ip,
       clean.parse_inet(r.dst_ip)                AS dst_ip,
       clean.parse_port(r.dst_port)              AS dst_port,
       clean.map_value('protocol', r.protocol)   AS protocol,
       clean.map_value('fw_action', r.action)    AS action,
       clean.parse_bytes(r.bytes)                AS bytes
FROM raw.firewall_logs r;

-- Syslog lines carry no year. The export year is assumed; a date that would land after the export
-- (e.g. a December line in a January export) belongs to the previous year.
UPDATE fw_staged SET log_time = log_time - interval '1 year'
WHERE log_time > ref.setting('extract_time')::timestamptz;

-- Firewall lines have no event ID. Two lines identical in every cleaned field (same second, hosts, port,
-- action and byte count) are treated as a duplicate export; a genuine repeat would differ in time or bytes.
-- Matching on CLEANED values catches copies that differ only in format ("tcp/443" vs "443").
CREATE TEMP TABLE fw_verdict AS
SELECT s.*,
       row_number() OVER (PARTITION BY log_time, src_ip, dst_ip, dst_port, protocol, action, bytes ORDER BY raw_id) AS copy_no
FROM fw_staged s;

ALTER TABLE fw_verdict ADD COLUMN reason text;
UPDATE fw_verdict SET reason =
    CASE WHEN log_time IS NULL                       THEN 'unparseable_time'
         WHEN copy_no > 1                            THEN 'duplicate'
         WHEN src_ip IS NULL OR dst_ip IS NULL       THEN 'invalid_ip'
         WHEN dst_port IS NULL                       THEN 'invalid_port'
         WHEN protocol IS NULL                       THEN 'unmapped_protocol'
         WHEN action IS NULL                         THEN 'unmapped_action'
    END;

INSERT INTO quarantine.records (source, raw_id, reason, raw_record)
SELECT 'firewall_logs', v.raw_id, v.reason, to_jsonb(r) - 'raw_id'
FROM fw_verdict v JOIN raw.firewall_logs r USING (raw_id)
WHERE v.reason IS NOT NULL;

CREATE TABLE clean.firewall_events (
    raw_id    bigint PRIMARY KEY,
    log_time  timestamptz NOT NULL,
    src_ip    inet NOT NULL,
    dst_ip    inet NOT NULL,
    dst_port  int  NOT NULL CHECK (dst_port BETWEEN 0 AND 65535),
    protocol  text NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    action    text NOT NULL CHECK (action IN ('allow', 'deny')),
    bytes     bigint CHECK (bytes >= 0),
    direction text NOT NULL CHECK (direction IN ('outbound', 'inbound', 'internal'))
);

-- Direction comes from RFC 1918 private ranges, using PostgreSQL's inet containment operator <<.
INSERT INTO clean.firewall_events
SELECT raw_id, log_time, src_ip, dst_ip, dst_port, protocol, action, bytes,
       CASE WHEN src_private AND dst_private THEN 'internal'
            WHEN src_private                 THEN 'outbound'
            ELSE 'inbound' END
FROM (SELECT v.*,
             (src_ip << '10.0.0.0/8' OR src_ip << '172.16.0.0/12' OR src_ip << '192.168.0.0/16') AS src_private,
             (dst_ip << '10.0.0.0/8' OR dst_ip << '172.16.0.0/12' OR dst_ip << '192.168.0.0/16') AS dst_private
      FROM fw_verdict v WHERE reason IS NULL) s;

CREATE INDEX ON clean.firewall_events (src_ip, dst_ip, dst_port, log_time);
