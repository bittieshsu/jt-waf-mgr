"""Hourly event counts kept next to the events, so a dashboard costs about the same with ten events an hour or a
million (0.4.54: the overview scanned every event of the window, about 60 µs each).

Four small tables, one row per hour and combination with a counter:
  ev_hour         site, origin, outcome, how it was decided
  ev_hour_family  site, origin, outcome, attack type ("other" when none)
  ev_hour_rule    site, origin, outcome, rule id
  ev_hour_src     site, origin, outcome, source address
SQLite triggers keep them in step with `events` whoever writes there (the collector, a one-off correction, the
retention purge, a test), and the migration that creates them counts the events already stored, in SQL.

A window [since, until) is read as the whole hours from these tables plus the partial hours at both ends from the
events themselves: the numbers are exactly those of a scan of the events.
"""

TABLES = {
    'ev_hour': ('decided_by', "COALESCE({r}.decided_by, '')"),
    'ev_hour_family': ('family', None),
    'ev_hour_rule': ('rule_id', None),
    'ev_hour_src': ('src_ip', '{r}.src_ip'),
}
COMMON = ('node_id', 'hour', 'host', 'origin', 'outcome')
FILTERABLE = ('host', 'origin', 'outcome')      # filters the tables can answer; anything else scans the events

# the attack types of a row as a JSON array ("other" when none), its rule ids as one (none: no row)
_FAMILIES = ("CASE WHEN trim({r}.families, ',') = '' THEN '[\"other\"]' "
             "ELSE '[\"' || replace(trim({r}.families, ','), ',', '\",\"') || '\"]' END")
_RULES = "'[' || trim({r}.rule_ids, ',') || ']'"


def _hour(r):
    return 'CAST({r}.ts / 3600 AS INTEGER)'.format(r=r)


def _sources(table, r):
    """(FROM clause, value expression) giving the rows of `table` one event `r` counts in."""
    if table == 'ev_hour_family':
        return "json_each(%s) j" % _FAMILIES.format(r=r), 'j.value'
    if table == 'ev_hour_rule':
        return "json_each(%s) j" % _RULES.format(r=r), 'CAST(j.value AS INTEGER)'
    return None, TABLES[table][1].format(r=r)


def _add_sql(table, r):
    dim = TABLES[table][0]
    src, val = _sources(table, r)
    cols = ', '.join(COMMON + (dim, 'n'))
    vals = "{r}.node_id, {h}, {r}.host, {r}.origin, {r}.outcome, {v}, 1".format(r=r, h=_hour(r), v=val)
    # "WHERE 1" keeps SQLite from reading ON CONFLICT as part of the SELECT
    return ('INSERT INTO %s(%s) SELECT %s%s WHERE 1 ON CONFLICT DO UPDATE SET n = n + 1;'
            % (table, cols, vals, ' FROM ' + src if src else ''))


def _sub_sql(table, r):
    dim = TABLES[table][0]
    src, val = _sources(table, r)
    match = "node_id = {r}.node_id AND hour = {h} AND host = {r}.host AND origin = {r}.origin AND outcome = {r}.outcome" \
        .format(r=r, h=_hour(r))
    if src:
        return 'UPDATE %s SET n = n - 1 WHERE %s AND %s IN (SELECT %s FROM %s);' % (table, match, dim, val, src)
    return 'UPDATE %s SET n = n - 1 WHERE %s AND %s = %s;' % (table, match, dim, val)


def create(c):
    """Tables, triggers and the counts of the events already stored (a migration step; c: the connection)."""
    for table, (dim, _) in TABLES.items():
        kind = 'INTEGER' if dim == 'rule_id' else 'TEXT'
        c.execute('CREATE TABLE %s (node_id TEXT NOT NULL, hour INTEGER NOT NULL, host TEXT NOT NULL, origin TEXT NOT NULL, '
                  'outcome TEXT NOT NULL, %s %s NOT NULL, n INTEGER NOT NULL, '
                  'PRIMARY KEY (hour, host, origin, outcome, %s, node_id)) WITHOUT ROWID' % (table, dim, kind, dim))
    c.execute('CREATE INDEX ev_hour_src_ip ON ev_hour_src(src_ip, hour)')
    c.execute('CREATE TRIGGER events_rollup_ins AFTER INSERT ON events BEGIN %s END'
              % ' '.join(_add_sql(t, 'new') for t in TABLES))
    c.execute('CREATE TRIGGER events_rollup_del AFTER DELETE ON events BEGIN %s END'
              % ' '.join(_sub_sql(t, 'old') for t in TABLES))
    c.execute('CREATE TRIGGER events_rollup_upd AFTER UPDATE OF node_id, ts, host, origin, outcome, decided_by, families, '
              'rule_ids, src_ip ON events BEGIN %s %s END'
              % (' '.join(_sub_sql(t, 'old') for t in TABLES), ' '.join(_add_sql(t, 'new') for t in TABLES)))
    # the events already there, in one pass per table (SQL: seconds even for millions of rows)
    for table, (dim, _) in TABLES.items():
        src, val = _sources(table, 'e')
        cols = ', '.join(COMMON + (dim, 'n'))
        c.execute('INSERT INTO %s(%s) SELECT e.node_id, %s, e.host, e.origin, e.outcome, %s, COUNT(*) FROM events e%s '
                  'GROUP BY 1, 2, 3, 4, 5, 6' % (table, cols, _hour('e'), val, ', ' + src if src else ''))


def purge(c, before_ts):
    """Drop the hours wholly before before_ts (call before deleting those events: their triggers then find nothing
    left to count down)."""
    h = int(before_ts // 3600)
    for t in TABLES:
        c.execute('DELETE FROM %s WHERE hour < ?' % t, (h,))
    c.execute('DELETE FROM ev_hour WHERE n <= 0')


def hours_of(since, until):
    """(h1, h2): the whole hours [h1, h2) inside [since, until); None, None when there is none."""
    h1 = -int(-since // 3600)
    h2 = int(until // 3600)
    return (h1, h2) if h2 > h1 else (None, None)


def _split(s):
    return [x for x in (s or '').strip(',').split(',') if x]


def _raw(db, table, since, until, where, args, group, by_hour):
    """The same groups from the events of [since, until): only ever the partial hours at the ends."""
    dim = TABLES[table][0]
    out = {}
    for r in db.q('SELECT ts, host, origin, outcome, decided_by, families, rule_ids, src_ip FROM events '
                  'WHERE ts>=? AND ts<?' + where, (since, until) + tuple(args)):
        if table == 'ev_hour':
            dims = [r['decided_by'] or '']
        elif table == 'ev_hour_family':
            dims = _split(r['families']) or ['other']
        elif table == 'ev_hour_rule':
            dims = [int(x) for x in _split(r['rule_ids']) if x.lstrip('-').isdigit()]
        else:
            dims = [r['src_ip']]
        row = {'hour': int(r['ts'] // 3600), 'host': r['host'], 'origin': r['origin'], 'outcome': r['outcome']}
        for d in dims:
            row[dim] = d
            k = ((row['hour'],) if by_hour else ()) + tuple(row[c] for c in group)
            out[k] = out.get(k, 0) + 1
    return out


def window(db, table, since, until, flt=None, group=None, by_hour=False):
    """{([hour,] *group): n} for the events of [since, until), exactly. group: the columns to count by (default all
    of the table's); SQLite adds the rows up, so only the groups asked for come back.
    flt: {'host'|'origin'|'outcome': value} and {'not_host'|'not_origin'|'not_outcome': value}."""
    dim = TABLES[table][0]
    group = tuple(group or ('host', 'origin', 'outcome', dim))
    where, args = '', []
    for k, v in (flt or {}).items():
        col = k[4:] if k.startswith('not_') else k
        if col not in FILTERABLE:
            raise ValueError(k)
        where += ' AND %s %s ?' % (col, '!=' if k.startswith('not_') else '=')
        args.append(v)
    h1, h2 = hours_of(since, until)
    if h1 is None:
        return _raw(db, table, since, until, where, args, group, by_hour)
    out = {}
    for a, b in ((since, h1 * 3600), (h2 * 3600, until)):
        if b > a:
            for k, n in _raw(db, table, a, b, where, args, group, by_hour).items():
                out[k] = out.get(k, 0) + n
    cols = (('hour',) if by_hour else ()) + group
    sql = ', '.join(cols)
    for r in db.q('SELECT %s, SUM(n) n FROM %s WHERE hour >= ? AND hour < ?%s GROUP BY %s HAVING SUM(n) > 0'
                  % (sql, table, where, sql), (h1, h2) + tuple(args)):
        k = tuple(r[c] for c in cols)
        out[k] = out.get(k, 0) + r['n']
    return out
