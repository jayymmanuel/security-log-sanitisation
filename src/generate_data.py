"""Generate messy, realistic security log exports for Northbridge Logistics (fictional).

Standard library only. Fixed seed, so every run produces identical files.
Writes:
  data/raw/hr_directory.csv      HR export of staff accounts
  data/raw/auth_events.csv       sign-in events merged from two domain controllers and Entra ID (Azure AD)
  data/raw/vpn_sessions.csv      VPN appliance session export
  data/raw/firewall_logs.csv     perimeter firewall connection log
  data/ground_truth/planted_incidents.csv   the attacks deliberately hidden in the logs

Each source has realistic defects (mixed formats, placeholders, duplicates, bad values)
and five planted incidents that the SQL pipeline must surface after sanitisation.
"""
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

SEED = 2026
rng = random.Random(SEED)
ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'data' / 'raw'
TRUTH = ROOT / 'data' / 'ground_truth'
RAW.mkdir(parents=True, exist_ok=True)
TRUTH.mkdir(parents=True, exist_ok=True)

UTC = timezone.utc
LONDON = ZoneInfo('Europe/London')
START = datetime(2026, 10, 1, tzinfo=UTC)
DAYS = 31
DOMAIN = 'northbridge.co.uk'

FIRST = ['James', 'Olivia', 'Mohammed', 'Amelia', 'Oliver', 'Isla', 'Harry', 'Ava', 'Jack', 'Mia', 'George', 'Sophia',
         'Noah', 'Grace', 'Leo', 'Lily', 'Arthur', 'Freya', 'Oscar', 'Emily', 'Priya', 'Aisha', 'Daniel', 'Chloe',
         'Samuel', 'Zara', 'Thomas', 'Ella', 'Kwame', 'Hannah', 'Ravi', 'Sofia', 'Lewis', 'Megan', 'Tariq', 'Ruby']
LAST = ['Smith', 'Jones', 'Patel', 'Williams', 'Brown', 'Taylor', 'Davies', 'Evans', 'Wilson', 'Thomas', 'Johnson',
        'Roberts', 'Walker', 'Wright', 'Robinson', 'Thompson', 'White', 'Hughes', 'Edwards', 'Green', 'Hall', 'Wood',
        'Khan', 'Ali', 'Clarke', 'Lewis', 'Mensah', 'Okafor', 'Shah', 'Murphy', 'Kelly', 'Harris', 'Martin', 'Cooper']
DEPTS = ['Operations', 'Warehouse', 'Finance', 'IT', 'Human Resources', 'Sales', 'Customer Service', 'Transport']


# ---------------------------------------------------------------- HR directory
def make_staff(n=240):
    staff, used = [], set()
    # Accounts the planted incidents rely on, created first so their usernames are fixed.
    fixed = [('Meera', 'Patel', 'Finance'), ('Adam', 'Green', 'Sales')]
    names = fixed + [(rng.choice(FIRST), rng.choice(LAST), rng.choice(DEPTS)) for _ in range(n - len(fixed))]
    for i, (first, last, dept) in enumerate(names):
        base = (first[0] + last).lower()
        user, k = base, 2
        while user in used:
            user, k = f'{base}{k}', k + 1
        used.add(user)
        staff.append(dict(employee_id=f'E{1001 + i}', first=first, last=last, username=user, dept=dept,
                          status='Active', leave_date=None))
    return staff


staff = make_staff()
by_user = {s['username']: s for s in staff}
BRUTE_USER, TRAVEL_USER = 'mpatel', 'agreen'
assert BRUTE_USER in by_user and TRAVEL_USER in by_user

# 12 leavers. Three keep signing in after leaving (planted). Their UK-format leave dates are chosen so that
# a US-style (MDY) date cast reads them as November/December, hiding the incident.
pool = [s for s in staff if s['username'] not in (BRUTE_USER, TRAVEL_USER)]
leavers = rng.sample(pool, 12)
planted_leavers = leavers[:3]
leave_dates = [datetime(2026, 10, 11), datetime(2026, 10, 12), datetime(2026, 10, 9)]
for s, d in zip(planted_leavers, leave_dates):
    s['status'], s['leave_date'] = 'Leaver', d
for s in leavers[3:]:
    s['status'], s['leave_date'] = 'Leaver', datetime(2026, 9, 1) + timedelta(days=rng.randint(0, 50))
leaver_ids = {s['employee_id'] for s in leavers}


def fmt_leave(d, idx):
    if d is None:
        return rng.choice(['', '', '', 'N/A', '-'])
    # Planted leavers: UK dd/mm/yyyy (the trap). Others: a mix of UK, ISO and long-form dates.
    if idx < 3 or rng.random() < 0.5:
        return d.strftime('%d/%m/%Y')
    return rng.choice([d.strftime('%Y-%m-%d'), d.strftime('%d %b %Y'), d.strftime('%d-%m-%Y')])


def messy_status(s):
    if s['status'] == 'Active':
        return rng.choice(['Active', 'Active', 'active', 'ACTIVE', ' Active ', 'Current'])
    return rng.choice(['Leaver', 'leaver', 'Terminated', 'TERMINATED', 'Left', 'Inactive'])


def messy_dept(d):
    variants = {'Human Resources': ['Human Resources', 'HR', 'H.R.', 'human resources'],
                'IT': ['IT', 'I.T.', 'Information Technology', 'it '],
                'Customer Service': ['Customer Service', 'Customer Services', 'customer service']}
    v = variants.get(d, [d, d.upper(), d.lower(), f' {d} '])
    return rng.choice(v)


hr_rows = []
for s in staff:
    idx = planted_leavers.index(s) if s in planted_leavers else 99
    email = f"{s['username']}@{DOMAIN}"
    hr_rows.append([s['employee_id'], f"{s['first']} {s['last']}",
                    rng.choice([email, email, email.upper(), f' {email}']), messy_dept(s['dept']),
                    messy_status(s), fmt_leave(s['leave_date'], idx)])
# Defects: exact duplicate rows from a double export, and two rows with no employee ID.
hr_rows += [list(r) for r in rng.sample(hr_rows, 6)]
hr_rows += [['', 'Contractor Temp', f'temp01@{DOMAIN}', 'Warehouse', 'Active', ''],
            ['  ', 'Agency Picker', f'agency.picker@{DOMAIN}', 'warehouse', 'active', '']]
rng.shuffle(hr_rows)
with open(RAW / 'hr_directory.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['employee_id', 'full_name', 'email', 'department', 'employment_status', 'leave_date'])
    w.writerows(hr_rows)

# ---------------------------------------------------------------- Sign-in events
OFFICE_NETS = ['10.1.{}.{}', '10.2.{}.{}']
VPN_POOL = '10.20.{}.{}'


def internal_ip():
    tmpl = rng.choice(OFFICE_NETS + [VPN_POOL])
    return tmpl.format(rng.randint(0, 9), rng.randint(2, 254))


def in_dst_gap(dt):
    """Avoid the repeated local hour when UK clocks go back (25 Oct 2026, 00:00-01:00 UTC)."""
    return datetime(2026, 10, 25, 0, 0, tzinfo=UTC) <= dt < datetime(2026, 10, 25, 1, 0, tzinfo=UTC)


def fmt_time(dt, system):
    r = rng.random()
    if system.startswith('DC01'):
        if r < 0.003:
            return rng.choice(['', '31/02/2026 10:00:00', 'NULL'])
        return dt.astimezone(LONDON).strftime('%d/%m/%Y %H:%M:%S')          # UK local time
    if system.startswith('DC02'):
        if r < 0.15:
            return str(int(dt.timestamp() * 1000))                           # epoch milliseconds
        return str(int(dt.timestamp()))                                      # epoch seconds
    if r < 0.003:
        return rng.choice(['NaN', 'invalid'])
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ') if r < 0.7 else dt.astimezone(LONDON).isoformat()


def fmt_user(u, system, noisy=True):
    if system.startswith('DC'):
        v = rng.choice([f'CORP\\{u}', f'CORP\\{u}', u, f'corp\\{u}'])
    else:
        v = f'{u}@{DOMAIN}'
    if noisy:
        r = rng.random()
        if r < 0.05:
            v = v.upper() if rng.random() < 0.5 else v.title()
        elif r < 0.08:
            v = f' {v} '
    return v


def fmt_ip(ip, noisy=True):
    if not noisy:
        return ip
    r = rng.random()
    if r < 0.02:
        return '.'.join(f'{int(o):03d}' for o in ip.split('.'))              # zero-padded octets
    if r < 0.03:
        return f'::ffff:{ip}'                                                # IPv4-mapped IPv6
    if r < 0.05:
        return rng.choice(['-', 'N/A', '', 'unknown'])
    if r < 0.06:
        o = ip.split('.'); o[3] = str(rng.randint(256, 999)); return '.'.join(o)   # impossible octet
    if r < 0.09:
        return f' {ip} '
    return ip


SYSTEM_LABELS = {'DC01': ['DC01', 'DC01', 'dc01', ' DC01'], 'DC02': ['DC02', 'dc02'],
                 'ENTRA': ['EntraID', 'EntraID', 'Azure AD', 'AzureAD', 'AAD']}


def outcome(success, system):
    if system.startswith('DC'):
        return '4624' if success else rng.choice(['4625', '4625', '4771'])
    return rng.choice(['0', 'Success', 'success', 'SUCCESS']) if success else rng.choice(['50126', 'Failure', 'failure', 'FAILED'])


auth, ev = [], 0


def add_auth(dt, user, ip, success, system=None, noisy=True, logon_type=None):
    global ev
    system = system or rng.choices(['DC01', 'DC02', 'ENTRA'], [0.45, 0.2, 0.35])[0]
    if system.startswith('DC01') and in_dst_gap(dt):
        system = 'ENTRA'
    ev += 1
    eid = {'DC01': f'DC01-{ev:07d}', 'DC02': f'DC02-{ev:07d}', 'ENTRA': f'{rng.getrandbits(64):016x}'}[system]
    lt = logon_type or rng.choice(['2', '3', '10', 'Interactive', 'Network', 'RemoteInteractive'] if system != 'ENTRA'
                                  else ['Browser', 'Mobile app', 'browser'])
    auth.append([eid, rng.choice(SYSTEM_LABELS[system]), fmt_time(dt, system),
                 fmt_user(user, system, noisy) if user else rng.choice(['', '-', 'N/A']),
                 fmt_ip(ip, noisy), outcome(success, system), lt])


active = [s for s in staff if s['employee_id'] not in leaver_ids]
for day in range(DAYS):
    d = START + timedelta(days=day)
    weekend = d.weekday() >= 5
    for s in active:
        if weekend and rng.random() > 0.08:
            continue
        for _ in range(rng.randint(1, 5)):
            t = d + timedelta(hours=rng.uniform(7, 18.5))
            ip = internal_ip()
            if rng.random() < 0.06:                                      # typo then success
                add_auth(t, s['username'], ip, False)
                t += timedelta(seconds=rng.randint(5, 60))
            add_auth(t, s['username'], ip, True)
    for s in leavers[3:]:                                                # leavers sign in only before leaving
        if d.replace(tzinfo=None) < s['leave_date'] and not weekend:
            add_auth(d + timedelta(hours=rng.uniform(8, 17)), s['username'], internal_ip(), True)

truth = []

# Incident 1: brute force against mpatel from one IP, 45 failures in 12 minutes, then a success.
# Username and IP formats vary per attempt, so a naive per-raw-value count never reaches the threshold.
bf_ip, t0 = '185.220.101.47', datetime(2026, 10, 8, 2, 14, tzinfo=UTC)
for i in range(45):
    sysname = rng.choice(['DC01', 'ENTRA'])
    add_auth(t0 + timedelta(seconds=16 * i), BRUTE_USER, bf_ip, False, sysname)
add_auth(t0 + timedelta(seconds=16 * 45 + 20), BRUTE_USER, bf_ip, True, 'ENTRA')
truth.append(['brute_force', BRUTE_USER, bf_ip, '2026-10-08', '45 failures in 12 minutes then a successful sign-in'])

# Incident 2: password spray. One IP, one attempt per account, 35 accounts in 25 minutes.
sp_ip, t0 = '91.240.118.5', datetime(2026, 10, 14, 22, 40, tzinfo=UTC)
targets = rng.sample([s['username'] for s in active], 28) + ['admin', 'administrator', 'test', 'backup', 'scanner', 'svc_sql', 'guest']
for i, u in enumerate(targets):
    add_auth(t0 + timedelta(seconds=43 * i), u, sp_ip, False, 'ENTRA')
truth.append(['password_spray', 'multiple', sp_ip, '2026-10-14', '35 accounts, one failed attempt each, in 25 minutes'])

# Incident 3: three leavers keep signing in after their leave date.
for s in planted_leavers:
    for k in range(rng.randint(2, 4)):
        t = datetime(2026, 10, 18 + k * 3, tzinfo=UTC) + timedelta(hours=rng.uniform(19, 23))
        add_auth(t, s['username'], f'82.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(2, 250)}', True, 'ENTRA')
    truth.append(['leaver_sign_in', s['username'], '', s['leave_date'].strftime('%Y-%m-%d'), 'successful sign-ins after leave date'])

# Defects: re-ingested duplicates (exact, and with whitespace drift on the same event ID), clock-skewed future rows.
dups = [list(r) for r in rng.sample(auth, int(len(auth) * 0.015))]
drift = []
for r in rng.sample(auth, int(len(auth) * 0.005)):
    r = list(r); r[3] = f'  {r[3].strip()}  '; drift.append(r)
for r in rng.sample(auth, 25):
    if r[1].strip().lower().startswith('entra') or r[1] in ('Azure AD', 'AzureAD', 'AAD'):
        r[2] = r[2].replace('2026-', '2027-', 1)
auth += dups + drift
rng.shuffle(auth)
with open(RAW / 'auth_events.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['event_id', 'source_system', 'event_time', 'username', 'src_ip', 'result', 'logon_type'])
    w.writerows(auth)

# ---------------------------------------------------------------- VPN sessions
COUNTRY_VARIANTS = {'GB': ['GB', 'UK', 'United Kingdom', 'gb', 'GBR', 'U.K.'], 'IE': ['IE', 'Ireland', 'IRL'],
                    'FR': ['FR', 'France', 'fra'], 'ES': ['ES', 'Spain'], 'NG': ['NG', 'Nigeria', 'NGA'],
                    'NL': ['NL', 'Netherlands', 'Holland']}


def fmt_bytes(n):
    r = rng.random()
    if r < 0.35:
        return f'{n / 1_048_576:.1f} MB'
    if r < 0.55:
        return f'{n / 1024:.0f}KB'
    if r < 0.7:
        return f'{n:,}'
    if r < 0.72:
        return rng.choice(['', '-'])
    return str(n)


vpn, sid = [], 0
remote_users = rng.sample([s['username'] for s in active if s['username'] != TRAVEL_USER], 70) + [TRAVEL_USER]
travellers = set(rng.sample(remote_users, 6))
for day in range(DAYS):
    d = START + timedelta(days=day)
    for u in remote_users:
        if rng.random() > 0.35:
            continue
        country = 'GB'
        if u in travellers and 10 <= day <= 14:
            country = rng.choice(['IE', 'FR', 'ES', 'NL'])                    # genuine business travel
        start = d + timedelta(hours=rng.uniform(6, 20))
        if in_dst_gap(start):
            start += timedelta(hours=2)
        dur = timedelta(minutes=rng.randint(10, 400))
        sid += 1
        vpn.append(dict(sid=sid, u=u, start=start, end=start + dur, country=country,
                        ip=f'{rng.choice([86, 92, 151, 213])}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(2, 250)}',
                        bin=rng.randint(200_000, 900_000_000), bout=rng.randint(50_000, 200_000_000)))
# Incident 4: impossible travel. agreen connects from GB, then from Nigeria 35 minutes after disconnecting.
t = datetime(2026, 10, 21, 8, 5, tzinfo=UTC)
for c, s0, mins in [('GB', t, 70), ('NG', t + timedelta(minutes=105), 50)]:
    sid += 1
    vpn.append(dict(sid=sid, u=TRAVEL_USER, start=s0, end=s0 + timedelta(minutes=mins), country=c,
                    ip='86.14.201.33' if c == 'GB' else '105.112.44.9', bin=rng.randint(10**6, 10**8), bout=rng.randint(10**5, 10**7)))
truth.append(['impossible_travel', TRAVEL_USER, '105.112.44.9', '2026-10-21', 'GB session then NG session 35 minutes later'])


def vpn_time(dt):
    return dt.astimezone(LONDON).isoformat(timespec='seconds') if rng.random() < 0.8 else dt.strftime('%Y-%m-%d %H:%M:%S UTC')


vpn_rows = []
for v in vpn:
    start, end = vpn_time(v['start']), vpn_time(v['end'])
    if v['u'] != TRAVEL_USER:
        r = rng.random()
        if r < 0.01:
            start, end = end, start                                          # end before start
        elif r < 0.03:
            end = ''                                                         # session still open at export
    vpn_rows.append([f'VPN-{v["sid"]:06d}', fmt_user(v['u'], 'ENTRA'), v['ip'], rng.choice(COUNTRY_VARIANTS[v['country']]),
                     start, end, fmt_bytes(v['bin']), fmt_bytes(v['bout'])])
vpn_rows += [list(r) for r in rng.sample(vpn_rows, 40)]
rng.shuffle(vpn_rows)
with open(RAW / 'vpn_sessions.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['session_id', 'username', 'client_ip', 'country', 'session_start', 'session_end', 'bytes_in', 'bytes_out'])
    w.writerows(vpn_rows)

# ---------------------------------------------------------------- Firewall
SERVICES = [(443, 'tcp', 0.55), (80, 'tcp', 0.12), (53, 'udp', 0.18), (123, 'udp', 0.03), (25, 'tcp', 0.02),
            (22, 'tcp', 0.03), (3389, 'tcp', 0.02), (8080, 'tcp', 0.05)]
EXTERNAL = [f'{a}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(2, 250)}' for a in rng.choices([13, 20, 23, 34, 52, 104, 142, 151, 172, 185, 216], k=400)]


def fmt_port(port, proto):
    r = rng.random()
    if r < 0.6:
        return str(port)
    if r < 0.75:
        return f'{proto}/{port}'
    if r < 0.85:
        return f'{port}/{proto.upper()}'
    if r < 0.95:
        return f' {port}'
    return rng.choice([str(port), '-', '70000', 'any'])                     # some unusable values


def fmt_action(allowed):
    return rng.choice(['ALLOW', 'allow', 'permit', 'accept', 'Accept']) if allowed else rng.choice(['DENY', 'deny', 'drop', 'Blocked', 'reject'])


def fw_time(dt):
    r = rng.random()
    if r < 0.6:
        return f'{dt:%b} {dt.day:>2} {dt:%H:%M:%S}'                         # syslog (RFC 3164): no year, space-padded day
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


fw = []
hosts = [f'10.1.{rng.randint(0, 9)}.{rng.randint(2, 254)}' for _ in range(180)]
for _ in range(82_000):
    port, proto, _w = rng.choices(SERVICES, [s[2] for s in SERVICES])[0]
    dt = START + timedelta(seconds=rng.randint(0, DAYS * 86400 - 1))
    allowed = not (port in (22, 3389) and rng.random() < 0.7) and rng.random() > 0.04
    fw.append([fw_time(dt), rng.choice(hosts), rng.choice(EXTERNAL), fmt_port(port, proto),
               rng.choice([proto, proto.upper()]), fmt_action(allowed), str(rng.randint(60, 2_000_000))])
# Incident 5: beaconing. One internal host calls one external IP on port 4444 every ~60 seconds for 6 hours.
bc_src, bc_dst, t0 = '10.1.7.15', '45.133.1.20', datetime(2026, 10, 17, 9, 0, tzinfo=UTC)
for i in range(360):
    dt = t0 + timedelta(seconds=60 * i + rng.uniform(-3, 3))
    fw.append([fw_time(dt), bc_src, bc_dst, fmt_port(4444, 'tcp'), rng.choice(['tcp', 'TCP']), fmt_action(True), str(rng.randint(300, 420))])
truth.append(['beaconing', bc_src, bc_dst, '2026-10-17', 'connection to port 4444 every ~60 seconds for 6 hours'])
fw += [list(r) for r in rng.sample(fw, 500)]
rng.shuffle(fw)
with open(RAW / 'firewall_logs.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['log_time', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'action', 'bytes'])
    w.writerows(fw)

with open(TRUTH / 'planted_incidents.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['incident_type', 'entity', 'indicator', 'incident_date', 'description'])
    w.writerows(truth)

print(f'HR {len(hr_rows):,} | auth {len(auth):,} | VPN {len(vpn_rows):,} | firewall {len(fw):,} | planted incidents {len(truth)}')
