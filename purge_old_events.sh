#!/bin/bash
# Deletes events older than 90 days and performs a vacuum
source /opt/sipmon/config.conf

PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -c \
    "DELETE FROM sip_events WHERE ts < NOW() - make_interval(days=>90);"
PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -c \
    "VACUUM ANALYZE sip_events;"
