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

# --- PostgreSQL performance tuning ---
PG_CONF=$(find /etc/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
if [ -n "$PG_CONF" ]; then
    info "Applying PostgreSQL performance tuning to $PG_CONF..."
    sed -i "s/^#*\s*max_connections\s*=.*/max_connections = 30/"       "$PG_CONF"
    sed -i "s/^#*\s*shared_buffers\s*=.*/shared_buffers = 512MB/"      "$PG_CONF"
    sed -i "s/^#*\s*effective_cache_size\s*=.*/effective_cache_size = 1500MB/" "$PG_CONF"
    sed -i "s/^#*\s*work_mem\s*=.*/work_mem = 8MB/"                    "$PG_CONF"
    sed -i "s/^#*\s*maintenance_work_mem\s*=.*/maintenance_work_mem = 128MB/" "$PG_CONF"
    systemctl restart postgresql
    info "PostgreSQL restarted with new settings"
else
    warn "postgresql.conf not found, skipping performance tuning"
fi

# =============================================================================
# 4. Python environment
# =============================================================================
info "Creating Python environment in /opt/octosip/venv..."
mkdir -p /opt/octosip/geoip

python3 -m venv /opt/octosip/venv
/opt/octosip/venv/bin/pip install -q --upgrade pip
/opt/octosip/venv/bin/pip install -q psycopg2-binary geoip2 flask flask-cors

# =============================================================================
# 5. Runtime configuration
# =============================================================================
info "Setting up runtime configuration..."

# Save the source directory so services can find the code
echo "OCTOSIP_DIR=$SCRIPT_DIR" > /opt/octosip/octosip.env

# Copy config.conf only on first install (preserve existing config on updates)
if [ ! -f /opt/octosip/config.conf ]; then
    cp "$SCRIPT_DIR/config.conf" /opt/octosip/config.conf
    info "config.conf copied to /opt/octosip/config.conf"
else
    info "config.conf already exists in /opt/octosip/, keeping existing configuration"
fi

# Make scripts executable
chmod +x "$SCRIPT_DIR/octosip_parser.py"
chmod +x "$SCRIPT_DIR/octosip_api.py"
chmod +x "$SCRIPT_DIR/purge_old_events.sh"
chmod +x "$SCRIPT_DIR/update_geoip.sh"
chmod +x "$SCRIPT_DIR/update.sh"

# =============================================================================
# 6. GeoIP
# =============================================================================
info "Downloading GeoIP databases..."
cd /opt/octosip/geoip
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
sed "s|OCTOSIP_DIR_PLACEHOLDER|$SCRIPT_DIR|g" \
    "$SCRIPT_DIR/10-octosip-honeypot.conf" > /etc/rsyslog.d/10-octosip-honeypot.conf
systemctl restart rsyslog
info "rsyslog configured"

# =============================================================================
# 9. Systemd services
# =============================================================================
info "Installing systemd services..."
cp "$SCRIPT_DIR/octosip-api.service" /etc/systemd/system/octosip-api.service
cp "$SCRIPT_DIR/octosip-web.service" /etc/systemd/system/octosip-web.service

systemctl daemon-reload
systemctl enable octosip-api octosip-web
systemctl restart octosip-api octosip-web
info "Services started"

# =============================================================================
# 10. Logrotate
# =============================================================================
info "Configuring logrotate..."
cat > /etc/logrotate.d/octosip << 'EOF'
/var/log/syslog {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
/var/log/octosip_parser.log {
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
 echo "0 3 * * * $SCRIPT_DIR/purge_old_events.sh >> /var/log/octosip_purge.log 2>&1"; \
 echo "0 4 * * 1 $SCRIPT_DIR/update_geoip.sh >> /var/log/geoip_update.log 2>&1") | crontab -

# =============================================================================
# 12. Verification
# =============================================================================
info "Checking services..."
sleep 3
systemctl is-active --quiet kamailio   && info "kamailio:    OK" || warn "kamailio:    FAIL"
systemctl is-active --quiet postgresql && info "postgresql:  OK" || warn "postgresql:  FAIL"
systemctl is-active --quiet rsyslog    && info "rsyslog:     OK" || warn "rsyslog:     FAIL"
systemctl is-active --quiet octosip-api && info "octosip-api:  OK" || warn "octosip-api:  FAIL"
systemctl is-active --quiet octosip-web && info "octosip-web:  OK" || warn "octosip-web:  FAIL"

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
echo "  3. To update to a newer version in the future:"
echo "     cd $SCRIPT_DIR && sudo ./update.sh"
echo ""
echo "  4. If you change /opt/octosip/config.conf after installation:"
echo "     systemctl restart octosip-api"
echo ""
echo "============================================================"
