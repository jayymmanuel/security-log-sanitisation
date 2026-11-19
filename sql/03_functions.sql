-- 03. Reusable "safe parse" functions. Each takes messy text and returns a typed value, or NULL when the
-- value cannot be trusted. They never raise an error, so one bad row can't stop the pipeline, and the
-- caller decides what NULL means (quarantine the row, or keep it with a flag).

-- Placeholders that mean "no value": blank, dash, N/A and friends all become NULL.
CREATE FUNCTION clean.null_if_blank(p text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN lower(btrim(p)) IN ('', '-', 'n/a', 'na', 'null', 'none', 'unknown', 'nan', '?')
                THEN NULL ELSE btrim(p) END
$$;

-- Timestamps arrive in five formats. Each pattern is matched explicitly; nothing relies on the
-- server's DateStyle, which would read 11/10/2026 as 10 November on a US-configured server.
--   1759479322                 epoch seconds (DC02)
--   1759479322000              epoch milliseconds (DC02)
--   08/10/2026 03:14:22        UK local wall-clock time (DC01), converted from Europe/London to UTC
--   2026-10-08T02:14:22Z / .123456+01:00 / " UTC"   ISO 8601 with an explicit zone, optional fractional seconds
--   Oct  8 02:14:22            syslog: no year, so the export year is supplied
-- SET timezone = 'UTC' fixes the session zone inside the function so results never depend on the caller.
CREATE FUNCTION clean.parse_event_time(p text, p_syslog_year int DEFAULT 2026) RETURNS timestamptz
LANGUAGE plpgsql STABLE SET timezone = 'UTC' AS $$
DECLARE v text := clean.null_if_blank(p);
BEGIN
    IF v IS NULL THEN RETURN NULL; END IF;
    IF v ~ '^\d{13}$' THEN RETURN to_timestamp(v::numeric / 1000); END IF;
    IF v ~ '^\d{10}$' THEN RETURN to_timestamp(v::numeric); END IF;
    IF v ~ '^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}$' THEN
        -- Validate the calendar date first: to_timestamp would roll 31/02 over into March.
        PERFORM make_date(substr(v, 7, 4)::int, substr(v, 4, 2)::int, substr(v, 1, 2)::int);
        RETURN to_timestamp(v, 'DD/MM/YYYY HH24:MI:SS')::timestamp AT TIME ZONE 'Europe/London';
    END IF;
    IF v ~ '^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z| UTC|[+-]\d{2}:\d{2})$' THEN   -- optional fractional seconds
        RETURN v::timestamptz;
    END IF;
    IF v ~ '^[A-Z][a-z]{2} [ 0-9]\d \d{2}:\d{2}:\d{2}$' THEN
        RETURN to_timestamp(p_syslog_year || ' ' || regexp_replace(v, '\s+', ' ', 'g'), 'YYYY Mon DD HH24:MI:SS');
    END IF;
    RETURN NULL;                                   -- unknown format: refuse to guess
EXCEPTION WHEN others THEN
    RETURN NULL;                                   -- matched a pattern but is not a real date (e.g. 31/02)
END $$;

-- Dates in the HR export: UK dd/mm/yyyy, dd-mm-yyyy, ISO yyyy-mm-dd, or "11 Oct 2026".
CREATE FUNCTION clean.parse_uk_date(p text) RETURNS date
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE v text := clean.null_if_blank(p);
BEGIN
    IF v IS NULL THEN RETURN NULL; END IF;
    IF v ~ '^\d{2}[/-]\d{2}[/-]\d{4}$' THEN
        RETURN make_date(substr(v, 7, 4)::int, substr(v, 4, 2)::int, substr(v, 1, 2)::int);
    END IF;
    IF v ~ '^\d{4}-\d{2}-\d{2}$' THEN
        RETURN make_date(substr(v, 1, 4)::int, substr(v, 6, 2)::int, substr(v, 9, 2)::int);
    END IF;
    IF v ~* '^\d{1,2} [a-z]{3} \d{4}$' THEN
        RETURN to_date(v, 'DD Mon YYYY');
    END IF;
    RETURN NULL;
EXCEPTION WHEN others THEN
    RETURN NULL;
END $$;

-- IP addresses: trims, unwraps IPv4-mapped IPv6 (::ffff:10.1.4.22), removes zero padding (010.001.004.022)
-- and rejects impossible octets (10.1.4.300). Returns PostgreSQL's native inet type, so later queries can
-- use network operators such as << '10.0.0.0/8'.
CREATE FUNCTION clean.parse_inet(p text) RETURNS inet
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE v text := clean.null_if_blank(p);
        o text[];
BEGIN
    IF v IS NULL THEN RETURN NULL; END IF;
    v := regexp_replace(v, '^::ffff:', '', 'i');
    IF v ~ '^\d{1,3}(\.\d{1,3}){3}$' THEN
        o := string_to_array(v, '.');
        IF o[1]::int > 255 OR o[2]::int > 255 OR o[3]::int > 255 OR o[4]::int > 255 THEN RETURN NULL; END IF;
        RETURN (o[1]::int || '.' || o[2]::int || '.' || o[3]::int || '.' || o[4]::int)::inet;
    END IF;
    IF v ~ ':' THEN RETURN v::inet; END IF;         -- genuine IPv6
    RETURN NULL;
EXCEPTION WHEN others THEN
    RETURN NULL;
END $$;

-- One identity per person. Three source formats collapse to the bare account name:
--   CORP\mpatel, mpatel@northbridge.co.uk, " MPatel " -> mpatel
CREATE FUNCTION clean.normalise_username(p text) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN u ~ '^[a-z0-9._-]+$' THEN u END
    FROM (SELECT regexp_replace(
                     regexp_replace(lower(clean.null_if_blank(p)), '^[a-z0-9.-]+\\', ''),   -- DOMAIN\user
                     '@' || replace(ref.setting('company_domain'), '.', '\.') || '$', '')    -- user@domain
                 AS u) s
$$;

-- Byte counts: "1.2 MB", "340KB", "1,048,576", "2048". Binary units (1 KB = 1024 bytes), as VPN appliances report.
CREATE FUNCTION clean.parse_bytes(p text) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE v text := lower(replace(clean.null_if_blank(p), ',', ''));
        m text[];
BEGIN
    IF v IS NULL THEN RETURN NULL; END IF;
    m := regexp_match(v, '^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$');
    IF m IS NULL THEN RETURN NULL; END IF;
    RETURN round(m[1]::numeric * CASE coalesce(m[2], 'b') WHEN 'b' THEN 1 WHEN 'kb' THEN 1024
                                     WHEN 'mb' THEN 1048576 ELSE 1073741824 END)::bigint;
END $$;

-- Ports: "443", "tcp/443", "443/TCP", " 443". Values outside 0-65535, "any" or "-" are unusable.
CREATE FUNCTION clean.parse_port(p text) RETURNS int
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN m[1]::int BETWEEN 0 AND 65535 THEN m[1]::int END
    FROM (SELECT regexp_match(btrim(p), '^(?:(?:tcp|udp)/)?(\d{1,5})(?:/(?:tcp|udp))?$', 'i') AS m) s
$$;
