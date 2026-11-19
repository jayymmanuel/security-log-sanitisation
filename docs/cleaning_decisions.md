# Cleaning decisions

Every rule in the pipeline, what it does, and why. Rules are listed in the order they run.

## General principles

| Principle | Why |
| --- | --- |
| Load raw data as `TEXT` | A typed column rejects or silently changes bad values on load. Text keeps every value visible for an explicit rule. |
| Parse with functions that return `NULL` instead of erroring | One bad row can't stop the pipeline. The calling script decides what `NULL` means for that field. |
| One reason per rejected row | Rules are checked in order and the first failure wins, so quarantine counts add up and each row is explained once. |
| Quarantine, never delete | Rejected rows are kept as JSON with their reason. They can be inspected, fixed at source or replayed. |
| Never guess | Unknown spellings, impossible dates and contradictory timestamps are flagged or quarantined, not filled in. |
| Don't remove the signal | In security data an "odd" value is often the attack. Cleaning must not filter it out. |

## Parse functions (`sql/03_functions.sql`)

**`null_if_blank`.** Turns `''`, `-`, `N/A`, `NULL`, `none`, `unknown`, `NaN` and `?` into a real `NULL`. Systems write "no value" in many ways; without this, `-` would count as an IP address and `N/A` as a date.

**`parse_event_time`.** Five timestamp formats, each matched by an explicit pattern:

| Format | Source | Handling |
| --- | --- | --- |
| `08/10/2026 03:14:22` | DC01 | UK local wall-clock time, converted from `Europe/London` to UTC. Handles BST before 25 Oct and GMT after. |
| `1759479322` | DC02 | Unix epoch seconds |
| `1759479322000` | DC02 | Unix epoch milliseconds, divided by 1,000 |
| `2026-10-08T02:14:22Z`, `.123456+01:00`, ` UTC` | Entra ID, VPN, firewall | ISO 8601 with explicit zone, optional fractional seconds |
| `Oct  8 02:14:22` | Firewall syslog | No year in the format, so the export year from `ref.settings` is used |

- Dates are validated before conversion: `to_timestamp('31/02/2026')` would silently roll over to 3 March.
- The function fixes its own time zone (`SET timezone = 'UTC'`), so results never depend on the caller's session.
- Anything that matches no pattern returns `NULL`. Guessing a format is how 11/10 becomes 10 November.

**`parse_uk_date`.** HR leave dates as `dd/mm/yyyy`, `dd-mm-yyyy`, `yyyy-mm-dd` or `11 Oct 2026`. Built field by field with `make_date()`, so a server with US date settings (`DateStyle = MDY`) gives the same answer. A test proves this.

**`parse_inet`.** Returns PostgreSQL's native `inet` type.
- Trims whitespace.
- Unwraps IPv4-mapped IPv6: `::ffff:10.1.4.22` becomes `10.1.4.22`.
- Removes zero padding: `010.001.004.022` becomes `10.1.4.22`. Without this, one host looks like two.
- Rejects impossible octets: `10.1.4.300` becomes `NULL`.
- Using `inet` enables network operators later, such as `src_ip << '10.0.0.0/8'`.

**`normalise_username`.** Collapses the three identity formats to one account name: `CORP\mpatel`, `mpatel@northbridge.co.uk` and ` MPatel ` all become `mpatel`. This single function is what makes the brute force visible.

**`parse_bytes`.** `1.2 MB`, `340KB`, `1,048,576`, `2048` become a byte count. Binary units (1 KB = 1,024 bytes), as network appliances report.

**`parse_port`.** `443`, `tcp/443`, `443/TCP`, ` 443` become `443`. Values outside 0 to 65,535, `any` and `-` return `NULL`.

## Value maps (`sql/04_value_maps.sql`)

69 mappings across 8 fields, stored in `ref.value_map`. Raw values are matched after lowercasing and trimming.

- **Why a table, not `CASE` statements:** the rules are visible data. A reviewer can read them, and adding a new spelling is an insert, not a code change.
- **Why unmapped values aren't guessed:** `audit.unmapped_values` lists any raw value with no mapping. A test fails if it isn't empty, so a new spelling forces a decision.
- **Sign-in results** combine two vocabularies: Windows event IDs (`4624` success, `4625` and `4771` failure) and Entra ID error codes (`0` success, `50126` invalid credentials).
- **Countries** map to ISO 3166-1 alpha-2. `UK` is common but not the ISO code; `GB` is.

## HR directory (`sql/05_clean_hr.sql`)

The HR directory defines who is a real employee and who has left, so it is cleaned first.

| Rule | Rows | Why |
| --- | ---: | --- |
| Missing employee ID → quarantine | 2 | No ID means no reliable identity; these are contractor rows typed in by hand |
| Duplicate employee ID → keep first | 6 | Same person exported twice |
| Username = email local part | 240 | Matches how sign-in systems identify people |
| Department and status mapped | 240 | 31 department spellings become 8; 10 status values become 2 |
| Leaver without a leave date → quarantine | 0 | A leaver check is impossible without the date |

## Sign-in events (`sql/06_clean_auth.sql`)

| Rule | Rows | Why |
| --- | ---: | --- |
| Duplicate (same system + event ID) → quarantine | 333 | Re-ingested events. Matched on **cleaned** values, so ` dc01` and `DC01` copies are recognised |
| Unparseable time → quarantine | 46 | Blank, `NaN`, `NULL`, `31/02/2026` |
| Time after the export → quarantine | 5 | Clock skew: an event can't be logged after the file was written |
| Unknown username → **keep**, label `unknown_account` | 7 | Attackers try `admin`, `test`, `backup`. Dropping these hides the spray |
| Missing or invalid IP → **keep**, IP `NULL`, `ip_issue` flag | 491 | The sign-in still happened; it just can't be tied to a network location |
| Link to employee | 16,615 | Adds `employee_id` and status (active or leaver) for the leaver check |

## VPN sessions (`sql/07_clean_vpn.sql`)

| Rule | Rows | Why |
| --- | ---: | --- |
| Duplicate session ID → quarantine | 40 | Same session exported twice |
| End before start → quarantine | 7 | One timestamp is wrong and nothing says which. Swapping would invent data |
| No end time → **keep**, `is_open = true` | 20 | Session still connected when the log was exported |
| Country mapped to ISO code | 753 | 15 spellings become 6 countries. Unmapped countries would be quarantined, because a guessed country could raise or hide an impossible-travel alert |
| Byte counts parsed | 753 | Placeholders become `NULL`, not zero: zero would claim no data moved |

## Firewall logs (`sql/08_clean_firewall.sql`)

| Rule | Rows | Why |
| --- | ---: | --- |
| Syslog year inferred | 49,787 | The format has no year. A date after the export would roll back a year (none did) |
| Duplicate (all cleaned fields equal) → quarantine | 500 | No event ID exists, so identity is the full record. A genuine repeat differs in time or bytes |
| Unusable port → quarantine | 3,051 | `any`, `-` and `70000` can't be analysed by port |
| Direction from RFC 1918 ranges | 79,309 | `outbound`, `inbound` or `internal`, using `inet` containment |

## Audit (`sql/09_audit.sql`)

- `audit.reconciliation`: raw rows = clean + duplicates + quarantined, per source.
- `audit.quarantine_summary`: count and one example per reason.
- `audit.unmapped_values`: raw categories with no mapping (expected empty).
- `audit.distinct_values`: distinct values per field before and after cleaning.

## Detections (`sql/10_detections.sql`)

Each detection runs on clean data and, as a naive version, on raw data. The naive versions are given parsed timestamps for free; everything else is used as exported.

| Detection | Rule | Why the raw version misses it |
| --- | --- | --- |
| Brute force | 10+ failures, one account, one IP, 15 minutes | Username and IP variants split 45 failures into small groups; most failure codes aren't `4625` or `Failure` |
| Password spray | One IP failing against 15+ accounts in 30 minutes | Only a quarter of Entra failures are labelled `Failure`; the rest are `50126`, `failure`, `FAILED` |
| Leaver sign-ins | Successful sign-in after the leave date | Usernames don't match HR emails exactly; `11/10/2026` read as 10 November |
| Impossible travel | Consecutive sessions in different countries less than 2 hours apart | Found on raw data too, but the companion "multiple countries" check flags 78 users instead of 6 |
| Beaconing | 50+ allowed outbound connections, one host to one destination and port, gap variation under 0.25 | Port spelled four ways splits the traffic, and the fragments have irregular gaps |
