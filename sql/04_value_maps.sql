-- 04. Value maps: every accepted spelling of a categorical value, mapped to one standard value.
-- Kept as a table, not CASE statements, so rules are visible, reviewable and extendable without code
-- changes. Raw values are matched after lower() and btrim(). A value with no mapping is never guessed:
-- it surfaces in audit.unmapped_values (and blocks the rows that depend on it).
CREATE TABLE ref.value_map (
    domain      text NOT NULL,
    raw_value   text NOT NULL,
    clean_value text NOT NULL,
    note        text,
    PRIMARY KEY (domain, raw_value)
);

INSERT INTO ref.value_map (domain, raw_value, clean_value, note) VALUES
-- Sign-in result. Windows logs event IDs, Entra ID logs error codes.
('auth_result', '4624',    'success', 'Windows: account successfully logged on'),
('auth_result', '4625',    'failure', 'Windows: account failed to log on'),
('auth_result', '4771',    'failure', 'Windows: Kerberos pre-authentication failed'),
('auth_result', '0',       'success', 'Entra ID error code 0 = success'),
('auth_result', '50126',   'failure', 'Entra ID: invalid username or password'),
('auth_result', 'success', 'success', NULL),
('auth_result', 'failure', 'failure', NULL),
('auth_result', 'failed',  'failure', NULL),
-- Logon type. Windows numbers and names describe the same thing.
('logon_type', '2',                 'interactive',        'Windows logon type 2'),
('logon_type', 'interactive',       'interactive',        NULL),
('logon_type', '3',                 'network',            'Windows logon type 3'),
('logon_type', 'network',           'network',            NULL),
('logon_type', '10',                'remote_interactive', 'Windows logon type 10 (RDP)'),
('logon_type', 'remoteinteractive', 'remote_interactive', NULL),
('logon_type', 'browser',           'browser',            'Entra ID client app'),
('logon_type', 'mobile app',        'mobile_app',         'Entra ID client app'),
-- Source system labels.
('source_system', 'dc01',     'DC01',     NULL),
('source_system', 'dc02',     'DC02',     NULL),
('source_system', 'entraid',  'ENTRA_ID', NULL),
('source_system', 'azure ad', 'ENTRA_ID', 'Entra ID was previously called Azure AD'),
('source_system', 'azuread',  'ENTRA_ID', NULL),
('source_system', 'aad',      'ENTRA_ID', NULL),
-- HR employment status.
('employment_status', 'active',     'active', NULL),
('employment_status', 'current',    'active', NULL),
('employment_status', 'leaver',     'leaver', NULL),
('employment_status', 'terminated', 'leaver', NULL),
('employment_status', 'left',       'leaver', NULL),
('employment_status', 'inactive',   'leaver', NULL),
-- HR department.
('department', 'operations',             'Operations',       NULL),
('department', 'warehouse',              'Warehouse',        NULL),
('department', 'finance',                'Finance',          NULL),
('department', 'it',                     'IT',               NULL),
('department', 'i.t.',                   'IT',               NULL),
('department', 'information technology', 'IT',               NULL),
('department', 'human resources',        'Human Resources',  NULL),
('department', 'hr',                     'Human Resources',  NULL),
('department', 'h.r.',                   'Human Resources',  NULL),
('department', 'sales',                  'Sales',            NULL),
('department', 'customer service',       'Customer Service', NULL),
('department', 'customer services',      'Customer Service', NULL),
('department', 'transport',              'Transport',        NULL),
-- Countries to ISO 3166-1 alpha-2. Note "UK" is not the ISO code: GB is.
('country', 'gb',             'GB', NULL),
('country', 'uk',             'GB', 'Common but not ISO'),
('country', 'u.k.',           'GB', NULL),
('country', 'gbr',            'GB', 'ISO alpha-3'),
('country', 'united kingdom', 'GB', NULL),
('country', 'ie',             'IE', NULL),
('country', 'irl',            'IE', NULL),
('country', 'ireland',        'IE', NULL),
('country', 'fr',             'FR', NULL),
('country', 'fra',            'FR', NULL),
('country', 'france',         'FR', NULL),
('country', 'es',             'ES', NULL),
('country', 'spain',          'ES', NULL),
('country', 'nl',             'NL', NULL),
('country', 'netherlands',    'NL', NULL),
('country', 'holland',        'NL', NULL),
('country', 'ng',             'NG', NULL),
('country', 'nga',            'NG', NULL),
('country', 'nigeria',        'NG', NULL),
-- Firewall action and protocol.
('fw_action', 'allow',   'allow', NULL),
('fw_action', 'permit',  'allow', NULL),
('fw_action', 'accept',  'allow', NULL),
('fw_action', 'deny',    'deny',  NULL),
('fw_action', 'drop',    'deny',  NULL),
('fw_action', 'blocked', 'deny',  NULL),
('fw_action', 'reject',  'deny',  NULL),
('protocol',  'tcp',     'tcp',   NULL),
('protocol',  'udp',     'udp',   NULL);

-- Look-up helper: returns NULL when a value has no mapping.
CREATE FUNCTION clean.map_value(p_domain text, p_raw text) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT clean_value FROM ref.value_map WHERE domain = p_domain AND raw_value = lower(btrim(p_raw))
$$;
