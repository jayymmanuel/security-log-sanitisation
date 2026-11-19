-- 05. HR directory -> clean.employees
-- The HR directory is the reference for "who is a real, current employee", so it is cleaned first.

CREATE TEMP TABLE hr_staged AS
SELECT r.raw_id,
       clean.null_if_blank(r.employee_id)                    AS employee_id,
       initcap(clean.null_if_blank(r.full_name))             AS full_name,
       lower(clean.null_if_blank(r.email))                   AS email,
       clean.normalise_username(r.email)                     AS username,     -- the email's local part
       clean.map_value('department', r.department)           AS department,
       clean.map_value('employment_status', r.employment_status) AS status,
       clean.parse_uk_date(r.leave_date)                     AS leave_date,
       clean.null_if_blank(r.leave_date)                     AS leave_date_text,
       -- Exact duplicate exports: same employee ID. Keep the first occurrence in the file.
       row_number() OVER (PARTITION BY upper(clean.null_if_blank(r.employee_id)) ORDER BY r.raw_id) AS copy_no
FROM raw.hr_directory r;

-- First failing rule wins, so each rejected row has exactly one reason.
CREATE TEMP TABLE hr_verdict AS
SELECT s.*,
       CASE WHEN employee_id IS NULL                         THEN 'missing_employee_id'
            WHEN copy_no > 1                                 THEN 'duplicate'
            WHEN username IS NULL                            THEN 'invalid_email'
            WHEN status IS NULL                              THEN 'unmapped_employment_status'
            WHEN leave_date_text IS NOT NULL AND leave_date IS NULL THEN 'unparseable_leave_date'
            WHEN status = 'leaver' AND leave_date IS NULL    THEN 'leaver_without_leave_date'
       END AS reason
FROM hr_staged s;

INSERT INTO quarantine.records (source, raw_id, reason, raw_record)
SELECT 'hr_directory', v.raw_id, v.reason, to_jsonb(r) - 'raw_id'
FROM hr_verdict v JOIN raw.hr_directory r USING (raw_id)
WHERE v.reason IS NOT NULL;

CREATE TABLE clean.employees (
    employee_id text PRIMARY KEY,
    full_name   text NOT NULL,
    email       text NOT NULL UNIQUE,
    username    text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9._-]+$'),
    department  text,                                  -- NULL when the HR value had no mapping
    status      text NOT NULL CHECK (status IN ('active', 'leaver')),
    leave_date  date,
    raw_id      bigint NOT NULL,
    CHECK (status = 'active' OR leave_date IS NOT NULL)
);

INSERT INTO clean.employees
SELECT upper(employee_id), full_name, email, username, department, status, leave_date, raw_id
FROM hr_verdict WHERE reason IS NULL;
