#!/bin/bash
# =============================================================================
# OctoSIP Honeypot - Install script
# Install Kamailio + Monitor on the same machine (Debian 12)
# Usage: ./install.sh
# =============================================================================

set -e

# --- Colors ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

# --- Root check ---
[ "$EUID" -ne 0 ] && error "Run this script as root"

# --- Load config ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/config.conf"
[ ! -f "$CONFIG" ] && error "config.conf not found in $SCRIPT_DIR"
source "$CONFIG"

# --- Validate required fields ---
[ "$MAXMIND_ACCOUNT_ID" = "YOUR_ACCOUNT_ID" ] && error "Fill in MAXMIND_ACCOUNT_ID in config.conf"
[ "$MAXMIND_LICENSE_KEY" = "YOUR_LICENSE_KEY" ] && error "Fill in MAXMIND_LICENSE_KEY in config.conf"

# --- Generate database password if using the default one ---
if [ "$DB_PASSWORD" = "changeme" ]; then
    DB_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)
    sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=$DB_PASSWORD/" "$CONFIG"
    info "Database password generated and saved in config.conf"
fi

# --- Detect server IP ---
SERVER_IP=$(hostname -I | awk '{print $1}')
info "Server IP detected: $SERVER_IP"

# =============================================================================
# 1. System packages
# =============================================================================
info "Updating packages..."
apt-get update -qq

info "Installing dependencies..."
apt-get install -y -qq \
    kamailio kamailio-extra-modules kamailio-autheph-modules \
    postgresql postgresql-client \
    python3 python3-venv python3-pip \
    rsyslog \
    curl wget tar \
    logrotate

# =============================================================================
# 2. Time zone
# =============================================================================
info "Configuring timezone: $TIMEZONE"
timedatectl set-timezone "$TIMEZONE"

# =============================================================================
# 3. PostgreSQL
# =============================================================================
info "Configuring PostgreSQL..."
systemctl enable postgresql
systemctl start postgresql

sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

sudo -u postgres psql -d "$DB_NAME" -c "
CREATE TABLE IF NOT EXISTS sip_events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip      INET,
    src_port    INT,
    method      VARCHAR(32),
    from_uri    TEXT,
    to_uri      TEXT,
    contact     TEXT,
    user_agent  TEXT,
    call_id     TEXT,
    status      VARCHAR(16),
    latitude    NUMERIC(9,6),
    longitude   NUMERIC(9,6),
    country     TEXT,
    city        TEXT,
    asn_number  BIGINT,
    asn_org     TEXT
);
CREATE INDEX IF NOT EXISTS idx_sip_events_ts     ON sip_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_sip_events_src_ip ON sip_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_sip_events_method ON sip_events (method);
GRANT ALL PRIVILEGES ON TABLE sip_events TO $DB_USER;
GRANT USAGE, SELECT ON SEQUENCE sip_events_id_seq TO $DB_USER;
"
info "PostgreSQL configured"

# =============================================================================
# 4. Python environment
# =============================================================================
info "Creating Python environment in /opt/sipmon..."
mkdir -p /opt/sipmon/geoip /opt/sipmon/www

python3 -m venv /opt/sipmon
/opt/sipmon/bin/pip install -q --upgrade pip
/opt/sipmon/bin/pip install -q psycopg2-binary geoip2 flask flask-cors

# =============================================================================
# 5. Copying files
# =============================================================================
info "Copying application files..."
cp "$SCRIPT_DIR/config.conf"       /opt/sipmon/config.conf
cp "$SCRIPT_DIR/sipmon_parser.py"  /opt/sipmon/sipmon_parser.py
cp "$SCRIPT_DIR/sipmon_api.py"     /opt/sipmon/sipmon_api.py
cp "$SCRIPT_DIR/purge_old_events.sh" /opt/sipmon/purge_old_events.sh
cp "$SCRIPT_DIR/update_geoip.sh"   /opt/sipmon/update_geoip.sh

chmod +x /opt/sipmon/sipmon_parser.py
chmod +x /opt/sipmon/sipmon_api.py
chmod +x /opt/sipmon/purge_old_events.sh
chmod +x /opt/sipmon/update_geoip.sh

# Replace IP in index.html
sed "s|SIPMON_SERVER_IP|$SERVER_IP|g" "$SCRIPT_DIR/index.html" > /opt/sipmon/www/index.html

# =============================================================================
# 6. GeoIP
# =============================================================================
info "Downloading GeoIP databases..."
cd /opt/sipmon/geoip
for DB in GeoLite2-City GeoLite2-ASN; do
    curl -fsSL -u "$MAXMIND_ACCOUNT_ID:$MAXMIND_LICENSE_KEY" \
        "https://download.maxmind.com/geoip/databases/$DB/download?suffix=tar.gz" \
        -o "$DB.tar.gz" && \
    tar xzf "$DB.tar.gz" --strip-components=1 --wildcards "*/$DB.mmdb" && \
    rm "$DB.tar.gz" && \
    info "$DB descargada"
done

# =============================================================================
# 7. Kamailio
# =============================================================================
info "Configuring Kamailio..."
# Replace SIP_PORT in kamailio.cfg
sed "s|SIP_PORT|$SIP_PORT|g" "$SCRIPT_DIR/kamailio.cfg" > /etc/kamailio/kamailio.cfg

# Configure Kamailio to start at boot
sed -i 's/^RUN_KAMAILIO=no/RUN_KAMAILIO=yes/' /etc/default/kamailio 2>/dev/null || true

systemctl enable kamailio
systemctl restart kamailio
info "Kamailio started"

# =============================================================================
# 8. rsyslog
# =============================================================================
info "Configuring rsyslog..."
cp "$SCRIPT_DIR/10-sip-honeypot.conf" /etc/rsyslog.d/10-sip-honeypot.conf
systemctl restart rsyslog
info "rsyslog configured"

# =============================================================================
# 9. Systemd services
# =============================================================================
info "Installing systemd services..."
cp "$SCRIPT_DIR/sipmon-api.service" /etc/systemd/system/sipmon-api.service
cp "$SCRIPT_DIR/sipmon-web.service" /etc/systemd/system/sipmon-web.service

systemctl daemon-reload
systemctl enable sipmon-api sipmon-web
systemctl restart sipmon-api sipmon-web
info "Services started"

# =============================================================================
# 10. Logrotate
# =============================================================================
info "Configuring logrotate..."
cat > /etc/logrotate.d/sipmon << 'EOF'
/var/log/syslog {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
/var/log/sipmon_parser.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP rsyslog
    endscript
}
EOF

# =============================================================================
# 11. Cron jobs
# =============================================================================
info "Configuring cron jobs..."
(crontab -l 2>/dev/null | grep -v 'purge_old_events\|update_geoip'; \
 echo "0 3 * * * /opt/sipmon/purge_old_events.sh >> /var/log/sipmon_purge.log 2>&1"; \
 echo "0 4 * * 1 /opt/sipmon/update_geoip.sh >> /var/log/geoip_update.log 2>&1") | crontab -

# =============================================================================
# 12. Verification
# =============================================================================
info "Checking services..."
sleep 3
systemctl is-active --quiet kamailio   && info "kamailio:    OK" || warn "kamailio:    FAIL"
systemctl is-active --quiet postgresql && info "postgresql:  OK" || warn "postgresql:  FAIL"
systemctl is-active --quiet rsyslog    && info "rsyslog:     OK" || warn "rsyslog:     FAIL"
systemctl is-active --quiet sipmon-api && info "sipmon-api:  OK" || warn "sipmon-api:  FAIL"
systemctl is-active --quiet sipmon-web && info "sipmon-web:  OK" || warn "sipmon-web:  FAIL"

# =============================================================================
# Post-installation
# =============================================================================
echo ""
echo "============================================================"
echo "  INSTALLATION COMPLETED"
echo "============================================================"
echo ""
echo "  Dashboard:  http://$SERVER_IP:8080"
echo "  API:        http://$SERVER_IP:5000/api/stats"
echo ""
echo "============================================================"
echo "  POST-INSTALLATION STEPS"
echo "============================================================"
echo ""
echo "  1. Open UDP/TCP port $SIP_PORT to this machine"
echo "     on your firewall/router (NAT if needed)."
echo ""
echo "  2. RFill in the config.conf file with your data:"
echo "     - MAXMIND_ACCOUNT_ID y MAXMIND_LICENSE_KEY"
echo "       (Free account at https://www.maxmind.com)"
echo "     - MAP_TARGET_LAT / MAP_TARGET_LON"
echo "       (Destination point coordinates on the map)"
echo "     - TIMEZONE  (default: Europe/Madrid)"
echo "     - DB_PASSWORD  (Change the password if you wish)"
echo ""
echo "  3. SAnd if you change config.conf after installation:"
echo "     systemctl restart sipmon-api"
echo "     systemctl restart sipmon-web"
echo ""
echo "============================================================"
