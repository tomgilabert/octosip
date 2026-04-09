#!/opt/octosip/venv/bin/python3
"""
octosip_parser.py — Reads Kamailio logs from stdin (rsyslog omprog), resolves GeoIP and ASN, and inserts them into PostgreSQL.
Flush: every 10 messages OR every 5 seconds (whichever comes first).
"""

import sys, re, logging, signal, threading, time, base64
import psycopg2, psycopg2.extras
import geoip2.database

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

DB_DSN         = "host=127.0.0.1 port=5432 dbname={} user={} password={}".format(
                    cfg.get('DB_NAME', 'octosip'),
                    cfg.get('DB_USER', 'octosip'),
                    cfg.get('DB_PASSWORD', ''))
GEOIP_DB       = "/opt/octosip/geoip/GeoLite2-City.mmdb"
GEOIP_ASN_DB   = "/opt/octosip/geoip/GeoLite2-ASN.mmdb"
BATCH_SIZE     = 10
FLUSH_INTERVAL = 5

RE_SIPREQ = re.compile(
    r'src=(?P<src_ip>[\d\.a-fA-F:]+):(?P<src_port>\d+)\s+'
    r'method=(?P<method>\S+)\s+'
    r'from=(?P<from_uri>\S+)\s+'
    r'to=(?P<to_uri>\S+)\s+'
    r'contact=(?P<contact>\S*)\s+'
    r'ua=(?P<user_agent>.*?)\s+'
    r'ci=(?P<call_id>\S+)'
)
RE_SIPREP = re.compile(
    r'src=(?P<src_ip>[\d\.a-fA-F:]+):(?P<src_port>\d+)\s+'
    r'status=(?P<status>\S+)\s+reason=(?P<reason>.*?)\s+ci=(?P<call_id>\S+)'
)
RE_PIKE = re.compile(
    r'src=(?P<src_ip>[\d\.a-fA-F:]+)\s+method=(?P<method>\S+)\s+ua=(?P<user_agent>.*)'
)
RE_AUTH = re.compile(
    r'src=(?P<src_ip>[\d\.a-fA-F:]+)\s+ua=(?P<user_agent>.*?)\s+from=(?P<from_uri>\S+)\s+auth_hdr=(?P<auth_hdr>.*)'
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.FileHandler('/var/log/octosip_parser.log')]
)
log = logging.getLogger('octosip')

INSERT_SQL = """
    INSERT INTO sip_events
        (src_ip, src_port, method, from_uri, to_uri, contact, user_agent,
         call_id, status, latitude, longitude, country, city, asn_number, asn_org,
         auth_username, auth_credentials)
    VALUES
        (%(src_ip)s, %(src_port)s, %(method)s, %(from_uri)s, %(to_uri)s,
         %(contact)s, %(user_agent)s, %(call_id)s, %(status)s,
         %(latitude)s, %(longitude)s, %(country)s, %(city)s,
         %(asn_number)s, %(asn_org)s, %(auth_username)s, %(auth_credentials)s)
"""

def connect():
    for attempt in range(10):
        try:
            conn = psycopg2.connect(DB_DSN)
            conn.autocommit = False
            log.info("PostgreSQL conectado")
            return conn
        except Exception as e:
            log.warning(f"Intento {attempt+1}/10: {e}")
            time.sleep(3)
    raise RuntimeError("No se pudo conectar a PostgreSQL")

def geoip_lookup(reader, ip):
    try:
        r = reader.city(ip)
        return (r.location.latitude, r.location.longitude,
                r.country.name, r.city.name)
    except Exception:
        return (None, None, None, None)

def asn_lookup(reader, ip):
    if reader is None:
        return (None, None)
    try:
        r = reader.asn(ip)
        return (r.autonomous_system_number, r.autonomous_system_organization)
    except Exception:
        return (None, None)

def parse_auth_header(auth_hdr):
    """Extract username and credentials from SIP Authorization header"""
    if not auth_hdr:
        return (None, None)

    username = None
    credentials = None

    # Basic auth: "Basic base64(username:password)"
    if auth_hdr.startswith('Basic '):
        try:
            encoded = auth_hdr[6:].strip()
            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            if ':' in decoded:
                username, password = decoded.split(':', 1)
                credentials = f"{username}/{password}"
            else:
                credentials = decoded
        except Exception:
            pass

    # Digest auth: extract username="value" and response hash
    if not credentials:
        match = re.search(r'username="?([^",]+)"?', auth_hdr)
        if match:
            username = match.group(1)
        # Extract response hash (Digest auth)
        resp_match = re.search(r'response="?([0-9a-fA-F]+)"?', auth_hdr)
        if resp_match:
            credentials = resp_match.group(1)

    return (username, credentials)

def parse_line(line, geo_reader, asn_reader):
    row = {
        'src_ip': None, 'src_port': None, 'method': None,
        'from_uri': None, 'to_uri': None, 'contact': None,
        'user_agent': None, 'call_id': None, 'status': None,
        'latitude': None, 'longitude': None, 'country': None, 'city': None,
        'asn_number': None, 'asn_org': None,
        'auth_username': None, 'auth_credentials': None,
    }
    matched = False

    if 'AUTH_ATTEMPT' in line:
        m = RE_AUTH.search(line)
        if m:
            d = m.groupdict()
            row.update({'src_ip': d['src_ip'], 'user_agent': d['user_agent'],
                        'from_uri': d['from_uri'], 'method': 'REGISTER'})
            auth_username, auth_credentials = parse_auth_header(d['auth_hdr'])
            row['auth_username'] = auth_username
            row['auth_credentials'] = auth_credentials
            matched = True
    elif 'SIPREQ' in line:
        m = RE_SIPREQ.search(line)
        if m:
            row.update(m.groupdict())
            row['src_port'] = int(row['src_port'])
            matched = True
    elif 'SIPREP' in line:
        m = RE_SIPREP.search(line)
        if m:
            d = m.groupdict()
            row.update({'src_ip': d['src_ip'], 'src_port': int(d['src_port']),
                        'status': d['status'], 'call_id': d['call_id'], 'method': 'REPLY'})
            matched = True
    elif 'PIKE_BLOCK' in line:
        m = RE_PIKE.search(line)
        if m:
            row.update(m.groupdict())
            row['method'] = 'PIKE:' + row.get('method', '')
            matched = True

    if matched and row['src_ip']:
        row['latitude'], row['longitude'], row['country'], row['city'] = \
            geoip_lookup(geo_reader, row['src_ip'])
        row['asn_number'], row['asn_org'] = \
            asn_lookup(asn_reader, row['src_ip'])
        return row
    return None

def main():
    conn       = connect()
    cur        = conn.cursor()
    geo_reader = geoip2.database.Reader(GEOIP_DB)

    try:
        asn_reader = geoip2.database.Reader(GEOIP_ASN_DB)
        log.info("ASN database cargada")
    except Exception as e:
        asn_reader = None
        log.warning(f"ASN database no disponible: {e}")

    batch = []
    lock  = threading.Lock()

    def flush():
        with lock:
            if not batch:
                return
            try:
                psycopg2.extras.execute_batch(cur, INSERT_SQL, batch)
                conn.commit()
                log.info(f"Insertados {len(batch)} eventos")
            except Exception as e:
                log.error(f"flush error: {e}")
                conn.rollback()
            batch.clear()

    def timer_flush():
        while True:
            time.sleep(FLUSH_INTERVAL)
            flush()
    threading.Thread(target=timer_flush, daemon=True).start()

    def shutdown(sig, frame):
        flush()
        geo_reader.close()
        if asn_reader:
            asn_reader.close()
        conn.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        row = parse_line(line, geo_reader, asn_reader)
        if row:
            with lock:
                batch.append(row)
            if len(batch) >= BATCH_SIZE:
                flush()
        if conn.closed:
            conn = connect()
            cur  = conn.cursor()

if __name__ == '__main__':
    main()
