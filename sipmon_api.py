#!/opt/octosip/bin/python3
"""
sipmon_api.py — API REST for the animated SIP attack map.
"""

from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import psycopg2, psycopg2.extras, psycopg2.pool
import logging, datetime

# --- Config ---
def load_config(path='/opt/octosip/config.conf'):
    cfg = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    cfg[k.strip()] = v.strip()
    except Exception:
        pass
    return cfg

cfg = load_config()

DB_DSN     = "host=127.0.0.1 port=5432 dbname={} user={} password={}".format(
                cfg.get('DB_NAME', 'sipmon'),
                cfg.get('DB_USER', 'sipmon'),
                cfg.get('DB_PASSWORD', ''))
TARGET_LAT = float(cfg.get('MAP_TARGET_LAT', 41.3874))
TARGET_LON = float(cfg.get('MAP_TARGET_LON', 2.1686))
TIMEZONE   = cfg.get('TIMEZONE', 'Europe/Madrid')

app  = Flask(__name__)
CORS(app)
pool = psycopg2.pool.ThreadedConnectionPool(2, 20, DB_DSN)

logging.basicConfig(level=logging.WARNING)

def query(sql, params=None):
    conn = pool.getconn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        pool.putconn(conn)

@app.route('/api/recent')
def recent():
    limit = min(int(request.args.get('limit', 50)), 1000)
    since = request.args.get('since', None)
    ip    = request.args.get('ip', None)
    if ip:
        rows = query("""
            SELECT id, ts, src_ip::text AS src_ip, method, user_agent,
                   country, city, latitude, longitude, from_uri, to_uri,
                   asn_number, asn_org
            FROM sip_events
            WHERE latitude IS NOT NULL AND host(src_ip) = %s
            ORDER BY ts DESC LIMIT 1
        """, (ip,))
    elif since:
        rows = query("""
            SELECT id, ts, src_ip::text AS src_ip, method, user_agent,
                   country, city, latitude, longitude, from_uri, to_uri,
                   asn_number, asn_org
            FROM sip_events
            WHERE latitude IS NOT NULL AND ts > %s
            ORDER BY ts DESC LIMIT %s
        """, (since, limit))
    else:
        rows = query("""
            SELECT id, ts, src_ip::text AS src_ip, method, user_agent,
                   country, city, latitude, longitude, from_uri, to_uri,
                   asn_number, asn_org
            FROM sip_events
            WHERE latitude IS NOT NULL
            ORDER BY ts DESC LIMIT %s
        """, (limit,))
    events = []
    for r in rows:
        events.append({
            'id':         r['id'],
            'ts':         r['ts'].isoformat(),
            'src_ip':     r['src_ip'],
            'method':     r['method'],
            'user_agent': r['user_agent'],
            'country':    r['country'],
            'city':       r['city'],
            'src_lat':    float(r['latitude'])  if r['latitude']  else None,
            'src_lon':    float(r['longitude']) if r['longitude'] else None,
            'dst_lat':    TARGET_LAT,
            'dst_lon':    TARGET_LON,
            'from_uri':   r['from_uri'],
            'to_uri':     r['to_uri'],
            'asn_number': r['asn_number'],
            'asn_org':    r['asn_org'],
        })
    return jsonify(events)

@app.route('/api/stats')
def stats():
    rows = query("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE ts > NOW() - INTERVAL '1 hour')   AS last_hour,
            COUNT(*) FILTER (WHERE ts > NOW() - INTERVAL '24 hours') AS last_day,
            COUNT(DISTINCT src_ip) FILTER (WHERE ts > NOW() - INTERVAL '24 hours') AS unique_ips,
            COUNT(*) FILTER (WHERE method LIKE 'PIKE%' AND ts > NOW() - INTERVAL '24 hours') AS blocked
        FROM sip_events
    """)
    return jsonify(dict(rows[0]))

@app.route('/api/top_ips')
def top_ips():
    rows = query("""
        SELECT src_ip::text AS ip, country, city,
               COUNT(*) AS requests, MAX(ts)::text AS last_seen
        FROM sip_events
        WHERE ts > NOW() - INTERVAL '24 hours'
        GROUP BY src_ip, country, city
        ORDER BY requests DESC LIMIT 15
    """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/top_countries')
def top_countries():
    rows = query("""
        SELECT country, COUNT(*) AS requests
        FROM sip_events
        WHERE ts > NOW() - INTERVAL '24 hours'
          AND country IS NOT NULL AND country != ''
        GROUP BY country ORDER BY requests DESC LIMIT 10
    """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/top_methods')
def top_methods():
    rows = query("""
        SELECT method, COUNT(*) AS requests
        FROM sip_events
        WHERE ts > NOW() - INTERVAL '24 hours'
          AND method IS NOT NULL AND method != ''
        GROUP BY method ORDER BY requests DESC LIMIT 10
    """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/top_asns')
def top_asns():
    rows = query("""
        SELECT asn_org, asn_number, COUNT(*) AS requests
        FROM sip_events
        WHERE ts > NOW() - INTERVAL '24 hours'
          AND asn_org IS NOT NULL AND asn_org != ''
        GROUP BY asn_org, asn_number ORDER BY requests DESC LIMIT 10
    """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/top_useragents')
def top_useragents():
    rows = query("""
        SELECT user_agent, COUNT(*) AS requests
        FROM sip_events
        WHERE ts > NOW() - INTERVAL '24 hours'
          AND user_agent IS NOT NULL AND user_agent != ''
        GROUP BY user_agent ORDER BY requests DESC LIMIT 10
    """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/heatmap')
def heatmap():
    rows = query("""
        SELECT latitude, longitude, COUNT(*) AS weight
        FROM sip_events
        WHERE latitude IS NOT NULL AND ts > NOW() - INTERVAL '24 hours'
        GROUP BY latitude, longitude
    """)
    return jsonify([[float(r['latitude']), float(r['longitude']), int(r['weight'])] for r in rows])

@app.route('/api/stats/hourly')
def hourly():
    rows = query("""
        SELECT EXTRACT(HOUR FROM ts AT TIME ZONE %s)::int AS hour,
               COUNT(*) AS count
        FROM sip_events
        WHERE ts > NOW() - INTERVAL '24 hours'
        GROUP BY hour ORDER BY hour
    """, (TIMEZONE,))
    counts = {int(r['hour']): int(r['count']) for r in rows}
    return jsonify([{'hour': h, 'count': counts.get(h, 0)} for h in range(24)])

@app.route('/api/stats/daily')
def daily():
    rows = query("""
        SELECT (ts AT TIME ZONE %s)::date AS day, COUNT(*) AS count
        FROM sip_events
        WHERE ts > NOW() - INTERVAL '30 days'
        GROUP BY day ORDER BY day
    """, (TIMEZONE,))
    return jsonify([{'day': str(r['day']), 'count': int(r['count'])} for r in rows])

@app.route('/api/iocs')
def iocs():
    hours = min(int(request.args.get('hours', 24)), 168)
    rows = query("""
        SELECT DISTINCT src_ip::text AS ip
        FROM sip_events
        WHERE ts > NOW() - (INTERVAL '1 hour' * %s)
          AND method NOT LIKE 'PIKE%%'
        ORDER BY ip
    """, (hours,))
    ips  = [r['ip'].split('/')[0] for r in rows]
    body = "# SIP Honeypot IOCs — last {}h — {}\n".format(
        hours, datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))
    body += "\n".join(ips) + "\n"
    return Response(body, mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename="iocs_{hours}h.txt"'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
