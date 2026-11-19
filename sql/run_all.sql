-- Run the whole pipeline from the project root:
--   psql -d seclogs -f sql/run_all.sql
-- Rebuilds every schema from scratch, so it is safe to run repeatedly.
\set ON_ERROR_STOP on
\set QUIET on
\pset pager off
SET client_min_messages = warning;

\echo '1/12  Creating schemas'
\ir 01_schemas.sql
\echo '2/12  Loading raw exports'
\ir 02_load_raw.sql
\echo '3/12  Creating parse functions'
\ir 03_functions.sql
\echo '4/12  Loading value maps'
\ir 04_value_maps.sql
\echo '5/12  Cleaning HR directory'
\ir 05_clean_hr.sql
\echo '6/12  Cleaning sign-in events'
\ir 06_clean_auth.sql
\echo '7/12  Cleaning VPN sessions'
\ir 07_clean_vpn.sql
\echo '8/12  Cleaning firewall logs'
\ir 08_clean_firewall.sql
\echo '9/12  Building audit views'
\ir 09_audit.sql
\echo '10/12 Building detections'
\ir 10_detections.sql
\echo '11/12 Running tests'
\ir 11_tests.sql
\echo '12/12 Exporting reports'
\ir 12_export_reports.sql

\echo
\echo '==== Reconciliation ===='
SELECT * FROM audit.reconciliation;
\echo '==== Planted incidents: found on raw data vs clean data ===='
SELECT incident_type, entity, found_on_raw_data, found_on_clean_data FROM detect.scorecard;
