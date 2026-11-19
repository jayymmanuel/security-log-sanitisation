-- 01. Schemas: one per stage, so every table's trust level is obvious from its name.
--   raw         exactly what the source systems exported, every column TEXT, nothing changed
--   ref         reference data: value maps, pipeline settings, planted incident list
--   clean       typed, standardised, deduplicated records that analysis may rely on
--   quarantine  rows that failed a rule, kept with the reason so nothing disappears silently
--   audit       row counts and data quality checks
--   detect      security detections built on clean data, plus naive versions on raw data
DROP SCHEMA IF EXISTS detect, audit, quarantine, clean, ref, raw CASCADE;
CREATE SCHEMA raw;
CREATE SCHEMA ref;
CREATE SCHEMA clean;
CREATE SCHEMA quarantine;
CREATE SCHEMA audit;
CREATE SCHEMA detect;

-- Settings the rules depend on, stored as data rather than buried in queries.
CREATE TABLE ref.settings (
    name  text PRIMARY KEY,
    value text NOT NULL,
    note  text
);
INSERT INTO ref.settings VALUES
    ('extract_time',  '2026-11-01 00:00:00+00', 'When the logs were exported. Events after this are clock skew.'),
    ('period_start',  '2026-10-01 00:00:00+00', 'First day the logs cover.'),
    ('company_domain','northbridge.co.uk',      'Stripped from UPN-style usernames.'),
    ('syslog_year',   '2026',                   'Syslog timestamps carry no year; this is the year of the export period.');

CREATE FUNCTION ref.setting(p_name text) RETURNS text
LANGUAGE sql STABLE AS $$ SELECT value FROM ref.settings WHERE name = p_name $$;

-- One quarantine table for every source. The original row is kept as JSON, so it can be inspected or replayed.
CREATE TABLE quarantine.records (
    source        text        NOT NULL,
    raw_id        bigint      NOT NULL,
    reason        text        NOT NULL,
    raw_record    jsonb       NOT NULL,
    quarantined_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source, raw_id)
);
