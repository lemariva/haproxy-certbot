#!/bin/bash
#
# Copyright [2025] [LeMaRiva Tech]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

# --- Replacement Logging Functions ---
log_info() { echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1"; }
log_warn() { echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" >&2; }
log_error(){ echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >&2; }
exit_nok() { log_error "$1"; exit 1; }

log_info "Preparing to start HAProxy..."

# -----------------------------------------------------------------------------
# 1. DEFINE CONSTANTS & VARIABLES
# -----------------------------------------------------------------------------

HA_PROXY_DIR=/usr/local/etc/haproxy
HAPROXY_PID_FILE="/var/run/haproxy.pid"
CERT_PERSISTENT_DIR="/addon_config/le_certs"
DEFAULT_PEM="${HA_PROXY_DIR}/default.pem"
TEMPLATE_FILE="/app/haproxy.cfg.template"

# Seed cli.ini into persistent config-dir root (so certbot loads it via --config-dir)
IMAGE_CLI_INI="/usr/local/etc/letsencrypt/cli.ini"
mkdir -p "${CERT_PERSISTENT_DIR}/work" "${CERT_PERSISTENT_DIR}/log"
if [ ! -f "${CERT_PERSISTENT_DIR}/cli.ini" ] && [ -f "${IMAGE_CLI_INI}" ]; then
    cp "${IMAGE_CLI_INI}" "${CERT_PERSISTENT_DIR}/cli.ini"
    chmod 644 "${CERT_PERSISTENT_DIR}/cli.ini"
    log_info "Seeded cli.ini to ${CERT_PERSISTENT_DIR}/cli.ini"
fi

# --- Role detection for VRRP MASTER/BACKUP (from keepalived) ---
KEEPALIVED_ROLE_FILE="/var/run/keepalived_role"

is_master() {
    if [ -f "${KEEPALIVED_ROLE_FILE}" ]; then
        ROLE=$(tr '[:lower:]' '[:upper:]' < "${KEEPALIVED_ROLE_FILE}" 2>/dev/null || true)
        if [ "${ROLE}" = "MASTER" ]; then
            return 0
        fi
    fi
    return 1
}

if is_master; then
    log_info "Detected node role: MASTER (Certbot renew enabled)."
else
    log_info "Detected node role: BACKUP or unknown (Certbot operations will be skipped; certificate refresh still enabled)."
fi

# -----------------------------------------------------------------------------
# 1b. ENVIRONMENT VARIABLE CONFIGURATION
# -----------------------------------------------------------------------------

DATA_PATH=${CONFIG_DATA_PATH:-}
STATS_USER=${CONFIG_STATS_USER:-}
STATS_PASSWORD=${CONFIG_STATS_PASSWORD:-}
HA_PRIMARY_IP=${CONFIG_HA_PRIMARY_IP:-}
HA_SECONDARY_IP=${CONFIG_HA_SECONDARY_IP:-}
HA_SERVICE_PORT=${CONFIG_HA_PORT:-}

HOSTNAME=$(hostname)
HAPROXY_CONFIG_FILE="/${DATA_PATH}/haproxy-${HOSTNAME}.cfg"
echo "export HAPROXY_CONFIG_FILE='${HAPROXY_CONFIG_FILE}'" > /etc/haproxy-env
chmod 644 /etc/haproxy-env
export HAPROXY_CONFIG_FILE
FINAL_CONFIG="${HAPROXY_CONFIG_FILE}"

LOG_LEVEL_RAW=${CONFIG_LOG_LEVEL:-}
LOG_LEVEL=$(echo "${LOG_LEVEL_RAW}" | awk '{print tolower($0)}')
if [ -z "${LOG_LEVEL}" ] || [ "${LOG_LEVEL}" = "null" ]; then
    LOG_LEVEL="info"
fi
if [ "${LOG_LEVEL}" = "warn" ]; then
    LOG_LEVEL="warning"
fi
log_info "HAProxy log level set to: ${LOG_LEVEL}"

CERT_EMAIL="${CONFIG_CERT_EMAIL:-}"
CERT_DOMAIN="${CONFIG_CERT_DOMAIN:-}"
CERTBOT_CERT_PATH="${CERT_PERSISTENT_DIR}/live/${CERT_DOMAIN}"

HOST_PORT_80_MAPPED=${MAPPED_HOST_PORT_80:-}
HOST_PORT_443_MAPPED=${MAPPED_HOST_PORT_443:-}
HOST_PORT_9999_MAPPED=${MAPPED_HOST_PORT_9999:-}

log_info "HAProxy mapped ports: HTTP=${HOST_PORT_80_MAPPED}, HTTPS=${HOST_PORT_443_MAPPED}, Stats=${HOST_PORT_9999_MAPPED}"

REQUIRED_VARS=("DATA_PATH" "STATS_USER" "STATS_PASSWORD" "HA_PRIMARY_IP" "HA_SECONDARY_IP" "HA_SERVICE_PORT")
for VAR_NAME in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!VAR_NAME}" ]; then
        exit_nok "Configuration error: Required environment variable '${VAR_NAME}' is not set."
    fi
done

# -----------------------------------------------------------------------------
# 2. CONFIGURATION TEMPLATING
# -----------------------------------------------------------------------------

mkdir -p "$(dirname "${FINAL_CONFIG}")" || exit_nok "Could not create data directory: ${DATA_PATH}"
rm -f "${HAPROXY_PID_FILE}"

log_info "Generating haproxy.cfg at ${FINAL_CONFIG}..."

< "${TEMPLATE_FILE}" \
    sed "
        s|__HOST_PORT_9999__|${HOST_PORT_9999_MAPPED}|g;
        s|__HAPROXY_STATS_USER__|${STATS_USER}|g;
        s|__HAPROXY_STATS_PASS__|${STATS_PASSWORD}|g;
        s|__HOST_PORT_80__|${HOST_PORT_80_MAPPED}|g;
        s|__HOST_PORT_443__|${HOST_PORT_443_MAPPED}|g;
        s|__HA_PRIMARY_IP__|${HA_PRIMARY_IP}|g;
        s|__HA_SECONDARY_IP__|${HA_SECONDARY_IP}|g;
        s|__HA_SERVICE_PORT__|${HA_SERVICE_PORT}|g;
        s|__CERT_DOMAIN_STRING__|${CERT_DOMAIN}|g;
        s|__LOG_LEVEL__|${LOG_LEVEL}|g;
    " > "${FINAL_CONFIG}.tmp"
mv "${FINAL_CONFIG}.tmp" "${FINAL_CONFIG}"

log_info "haproxy.cfg generated successfully."

# -----------------------------------------------------------------------------
# 3. CERTIFICATE LOGIC (Self-Signed & Let's Encrypt)
# -----------------------------------------------------------------------------

if [ ! -f "${DEFAULT_PEM}" ]; then
    log_info "Generating self-signed certificate..."

    TEMP_DIR=/tmp
    KEY=${TEMP_DIR}/haproxy_key.pem
    CERT=${TEMP_DIR}/haproxy_cert.pem
    SUBJ="/C=US/ST=somewhere/L=someplace/O=haproxy/OU=haproxy/CN=haproxy.selfsigned.invalid"

    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "${KEY}" -out "${CERT}" \
        -subj "${SUBJ}" &>/dev/null

    cat "${CERT}" "${KEY}" > "${DEFAULT_PEM}"
    rm -f "${KEY}" "${CERT}"
    log_info "Default self-signed certificate created."
fi

# -----------------------------------------------------------------------------
# 3b. CERTIFICATE REFRESH/RELOAD
#    Requirements:
#      - ALWAYS: if cert exists under live/, execute haproxy-refresh + haproxy-restart
#        at container startup (all nodes).
#      - ALWAYS: run watcher on all nodes to reload when cert content changes.
#      - RENEW/ISSUE: only on MASTER.
# -----------------------------------------------------------------------------

# Force refresh/restart if cert exists (ALWAYS at startup, all nodes)
force_haproxy_refresh_if_cert_present() {
    [ -n "${CERT_DOMAIN}" ] || return 0

    local fullchain="${CERTBOT_CERT_PATH}/fullchain.pem"
    local privkey="${CERTBOT_CERT_PATH}/privkey.pem"

    [ -f "$fullchain" ] || return 0
    [ -f "$privkey" ]  || return 0

    log_info "Certificate present under ${CERTBOT_CERT_PATH}. Forcing haproxy-refresh + haproxy-restart..."

    if command -v haproxy-refresh >/dev/null 2>&1; then
        haproxy-refresh || log_warn "haproxy-refresh failed."
        haproxy-restart || log_warn "haproxy-restart failed."
        return 0
    fi

    # Fallback: graceful reload if haproxy already running and pid exists
    if [ -f "${HAPROXY_PID_FILE}" ]; then
        local pid
        pid="$(cat "${HAPROXY_PID_FILE}" 2>/dev/null || true)"
        if [ -n "$pid" ]; then
            /usr/local/sbin/haproxy -f "${FINAL_CONFIG}" -D -p "${HAPROXY_PID_FILE}" -sf "$pid" \
                || log_warn "HAProxy graceful reload failed."
        fi
    fi
}

# Reload HAProxy ONLY if certificate content changed (used by watcher and after renew)
refresh_haproxy_if_cert_changed() {
    [ -n "${CERT_DOMAIN}" ] || return 0

    local fullchain="${CERTBOT_CERT_PATH}/fullchain.pem"
    local privkey="${CERTBOT_CERT_PATH}/privkey.pem"

    [ -f "$fullchain" ] || return 0
    [ -f "$privkey" ]  || return 0

    local state_file="${CERT_PERSISTENT_DIR}/.last_cert_hash_${CERT_DOMAIN}"
    local new_hash
    new_hash="$(cat "$fullchain" "$privkey" 2>/dev/null | sha256sum | awk '{print $1}')"

    local old_hash=""
    [ -f "$state_file" ] && old_hash="$(cat "$state_file" 2>/dev/null || true)"

    if [ -n "$new_hash" ] && [ "$new_hash" != "$old_hash" ]; then
        log_info "Detected updated certificate in ${CERTBOT_CERT_PATH}. Reloading HAProxy..."
        echo "$new_hash" > "$state_file"

        if command -v haproxy-refresh >/dev/null 2>&1; then
            haproxy-refresh || log_warn "haproxy-refresh failed."
            haproxy-restart || log_warn "haproxy-restart failed."
            return 0
        fi

        if [ -f "${HAPROXY_PID_FILE}" ]; then
            local pid
            pid="$(cat "${HAPROXY_PID_FILE}" 2>/dev/null || true)"
            if [ -n "$pid" ]; then
                /usr/local/sbin/haproxy -f "${FINAL_CONFIG}" -D -p "${HAPROXY_PID_FILE}" -sf "$pid" \
                    || log_warn "HAProxy graceful reload failed."
            fi
        fi
    fi
}

start_cert_watcher() {
    [ -n "${CERT_DOMAIN}" ] || return 0

    # Requirement: ALWAYS run refresh+restart at startup if cert exists
    force_haproxy_refresh_if_cert_present

    # Also initialize hash state / reload if needed
    refresh_haproxy_if_cert_changed

    if command -v inotifywait >/dev/null 2>&1; then
        log_info "Starting certificate watcher (inotify) for ${CERTBOT_CERT_PATH}..."
        (
            while true; do
                inotifywait -q -e close_write,move,create,attrib,delete "${CERTBOT_CERT_PATH}" 2>/dev/null || sleep 2
                refresh_haproxy_if_cert_changed
            done
        ) &
    else
        log_info "Starting certificate watcher (polling every 30s) for ${CERTBOT_CERT_PATH}..."
        (
            while true; do
                sleep 30
                refresh_haproxy_if_cert_changed
            done
        ) &
    fi
}

# Start watcher on ALL nodes
start_cert_watcher

# -----------------------------------------------------------------------------
# 3c. CERTBOT ISSUANCE + RENEW (MASTER ONLY)
# -----------------------------------------------------------------------------
start_cert_renewer_master_only() {
    [ -n "${CERT_DOMAIN}" ] || return 0

    if ! is_master; then
        log_info "Node is not MASTER according to ${KEEPALIVED_ROLE_FILE}. Certbot issuance/renew skipped (refresh watcher still active)."
        return 0
    fi

    if [ -z "${CERT_EMAIL}" ]; then
        exit_nok "Certbot is enabled via CONFIG_CERT_DOMAIN but CONFIG_CERT_EMAIL is missing."
    fi

    mkdir -p "${CERT_PERSISTENT_DIR}/work" "${CERT_PERSISTENT_DIR}/log"

    local fullchain_path="${CERTBOT_CERT_PATH}/fullchain.pem"

    # --- Initial issuance if missing ---
    if [ ! -f "${fullchain_path}" ]; then
        log_warn "No existing certificate found. Starting HAProxy temporarily for initial validation..."

        /usr/local/sbin/haproxy -f "${FINAL_CONFIG}" -D -p "${HAPROXY_PID_FILE}" &
        for i in {1..10}; do
            [ -f "${HAPROXY_PID_FILE}" ] && break
            sleep 1
        done

        if [ -f "${HAPROXY_PID_FILE}" ]; then
            HAPROXY_PID=$(cat "${HAPROXY_PID_FILE}")
        else
            log_error "HAProxy failed to start for Certbot validation."
            exit 1
        fi

        log_info "Attempting to obtain certificate for domain: ${CERT_DOMAIN}..."

        if /usr/bin/certbot-certonly \
            --config "${CERT_PERSISTENT_DIR}/cli.ini" \
            --config-dir "${CERT_PERSISTENT_DIR}" \
            --work-dir "${CERT_PERSISTENT_DIR}/work" \
            --logs-dir "${CERT_PERSISTENT_DIR}/log" \
            --email "${CERT_EMAIL}" \
            -d "${CERT_DOMAIN}"; then
            log_info "Certificate successfully obtained."
        else
            log_error "Certbot certificate request failed. HAProxy will use self-signed or existing certs."
        fi

        log_info "Stopping temporary HAProxy (PID ${HAPROXY_PID})."
        kill "${HAPROXY_PID}" 2>/dev/null || log_warn "Temporary HAProxy was already stopped."

        # Force refresh/restart if cert now exists; then do hash-based refresh as well
        force_haproxy_refresh_if_cert_present
        refresh_haproxy_if_cert_changed
    else
        log_info "Existing certificate found in ${fullchain_path}. MASTER will handle renewals."

        # At start on MASTER, still force refresh+restart if cert exists
        force_haproxy_refresh_if_cert_present
        refresh_haproxy_if_cert_changed
    fi

    # --- Periodic renew loop (MASTER only) ---
    # certbot will renew only when needed.
    local renew_interval="${CERTBOT_RENEW_INTERVAL_SECONDS:-43200}"  # default 12h
    log_info "Starting Certbot renew loop on MASTER (interval: ${renew_interval}s)..."

    (
        while true; do
            sleep "${renew_interval}"

            log_info "Running certbot renew (MASTER)..."
            if /usr/bin/certbot renew \
                --config "${CERT_PERSISTENT_DIR}/cli.ini" \
                --config-dir "${CERT_PERSISTENT_DIR}" \
                --work-dir "${CERT_PERSISTENT_DIR}/work" \
                --logs-dir "${CERT_PERSISTENT_DIR}/log"; then
                log_info "certbot renew finished (success)."
            else
                log_warn "certbot renew finished (with errors)."
            fi

            # If renew updated certs, watcher/hash refresh will reload; also force refresh if cert exists
            force_haproxy_refresh_if_cert_present
            refresh_haproxy_if_cert_changed
        done
    ) &
}

start_cert_renewer_master_only

# -----------------------------------------------------------------------------
# 4. NETWORKING (IPTABLES / TC SETUP)
# -----------------------------------------------------------------------------

IP=$(ip route get 1.1.1.1 | awk '/src/ {print $7}' | head -n 1)

if [ -n "$IP" ]; then
    log_info "Setting up IPTABLES/TC for TPROXY/loopback traffic on IP: ${IP}"

    if ! /usr/sbin/iptables -t mangle -C OUTPUT -p tcp -s "${IP}" --syn -j MARK --set-mark 1 2>/dev/null; then
        /usr/sbin/iptables -t mangle -I OUTPUT -p tcp -s "${IP}" --syn -j MARK --set-mark 1 \
            || log_warn "Failed to add iptables mangle OUTPUT rule for IP ${IP}"
    else
        log_info "IPTABLES mangle OUTPUT rule for IP ${IP} already present."
    fi

    if ! tc qdisc show dev lo | grep -q "handle 1: root prio"; then
        tc qdisc add dev lo root handle 1: prio bands 4 \
            || log_warn "TC qdisc add dev lo root failed."
    else
        log_info "TC root qdisc on lo already present."
    fi

    if ! tc qdisc show dev lo | grep -q "parent 1:1 handle 10:"; then
        tc qdisc add dev lo parent 1:1 handle 10: pfifo limit 1000 || log_warn "TC qdisc add 1:1 failed."
    fi
    if ! tc qdisc show dev lo | grep -q "parent 1:2 handle 20:"; then
        tc qdisc add dev lo parent 1:2 handle 20: pfifo limit 1000 || log_warn "TC qdisc add 1:2 failed."
    fi
    if ! tc qdisc show dev lo | grep -q "parent 1:3 handle 30:"; then
        tc qdisc add dev lo parent 1:3 handle 30: pfifo limit 1000 || log_warn "TC qdisc add 1:3 failed."
    fi

    if command -v nl-qdisc-list >/dev/null 2>&1; then
        if ! nl-qdisc-list --dev=lo 2>/dev/null | grep -q "id 40:"; then
            nl-qdisc-add --dev=lo --parent=1:4 --id=40: plug --limit 33554432 || log_warn "nl-qdisc-add plug failed."
        else
            log_info "nl-qdisc plug 40: already present on lo."
        fi
    else
        nl-qdisc-add --dev=lo --parent=1:4 --id=40: plug --limit 33554432 || log_warn "nl-qdisc-add plug failed."
    fi

    nl-qdisc-add --dev=lo --parent=1:4 --id=40: --update plug --release-indefinite || log_warn "nl-qdisc-add update failed."

    if ! tc filter show dev lo parent 1:0 2>/dev/null | grep -q "fw classid 1:4"; then
        tc filter add dev lo protocol ip parent 1:0 prio 1 handle 1 fw classid 1:4 || log_warn "TC filter add failed."
    else
        log_info "TC fw filter for mark 1 -> classid 1:4 already present."
    fi
else
    log_warn "Could not reliably determine IP address for TPROXY setup. Skipping IPTABLES/TC."
fi

# -----------------------------------------------------------------------------
# 5. START SUPERVISOR
# -----------------------------------------------------------------------------
log_info "Starting HAProxy via Supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
