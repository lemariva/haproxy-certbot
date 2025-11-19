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

# --- Replacement Logging Functions ---
# Simple functions to replace bashio::log.* functionality
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1"
}

log_warn() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" >&2
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >&2
}

exit_nok() {
    log_error "$1"
    exit 1
}

log_info "Preparing to start HAProxy..."

# -----------------------------------------------------------------------------
# 1. DEFINE CONSTANTS & VARIABLES
# -----------------------------------------------------------------------------

# Constants/Paths
HA_PROXY_DIR=/usr/local/etc/haproxy
HAPROXY_PID_FILE="/var/run/haproxy.pid"
CERT_PERSISTENT_DIR="/addon_config/le_certs"
DEFAULT_PEM="${HA_PROXY_DIR}/default.pem"
TEMPLATE_FILE="/app/haproxy.cfg.template"

# --- Environment Variable Configuration Mapping ---
# ASSUMPTION: The original config values are now passed as environment variables.

# Core Configuration
DATA_PATH=${CONFIG_DATA_PATH}
STATS_USER=${CONFIG_STATS_USER}
STATS_PASSWORD=${CONFIG_STATS_PASSWORD}
HA_SERVICE_IP=${CONFIG_HA_IP_ADDRESS} # Renamed for clarity in script
HA_SERVICE_PORT=${CONFIG_HA_PORT}     # Renamed for clarity in script
FINAL_CONFIG="/${DATA_PATH}/haproxy.cfg" 

# Log Level Configuration
LOG_LEVEL_RAW=${CONFIG_LOG_LEVEL}
LOG_LEVEL=$(echo "${LOG_LEVEL_RAW}" | awk '{print tolower($0)}')

if [ -z "${LOG_LEVEL}" ] || [ "${LOG_LEVEL}" = "null" ]; then
    LOG_LEVEL="info" # Default to INFO if not set
fi

# HAProxy uses 'warning', not 'warn', for syslog compatibility
if [ "${LOG_LEVEL}" = "warn" ]; then
    LOG_LEVEL="warning"
fi

log_info "HAProxy log level set to: ${LOG_LEVEL}"

# Certbot Variables
CERT_EMAIL="${CONFIG_CERT_EMAIL}"
CERT_DOMAIN="${CONFIG_CERT_DOMAIN}"
CERTBOT_CERT_PATH="${CERT_PERSISTENT_DIR}/live/${CERT_DOMAIN}"

# Host Ports (Replaced bashio::addon.port with environment variables)
HOST_PORT_80_MAPPED=${MAPPED_HOST_PORT_80}
HOST_PORT_443_MAPPED=${MAPPED_HOST_PORT_443}
HOST_PORT_9999_MAPPED=${MAPPED_HOST_PORT_9999}

log_info "HAProxy mapped ports: HTTP=${HOST_PORT_80_MAPPED}, HTTPS=${HOST_PORT_443_MAPPED}, Stats=${HOST_PORT_9999_MAPPED}"

# --- Check Required Variables ---
# Replaces bashio::config.require
REQUIRED_VARS=("DATA_PATH" "STATS_USER" "STATS_PASSWORD" "HA_SERVICE_IP" "HA_SERVICE_PORT")
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

# Copy the template and perform all SED replacements in a single pipeline
# Note: Variables used here must match the new environment variable names.
< "${TEMPLATE_FILE}" \
    sed "
        s|__HOST_PORT_9999__|${HOST_PORT_9999_MAPPED}|g;
        s|__HAPROXY_STATS_USER__|${STATS_USER}|g;
        s|__HAPROXY_STATS_PASS__|${STATS_PASSWORD}|g;
        s|__HOST_PORT_80__|${HOST_PORT_80_MAPPED}|g;
        s|__HOST_PORT_443__|${HOST_PORT_443_MAPPED}|g;
        s|__HA_SERVICE_IP__|${HA_SERVICE_IP}|g;
        s|__HA_SERVICE_PORT__|${HA_SERVICE_PORT}|g;
        s|__CERT_DOMAIN_STRING__|${CERT_DOMAIN}|g; 
        s|__LOG_LEVEL__|${LOG_LEVEL}|g;
    " > "${FINAL_CONFIG}.tmp"
mv "${FINAL_CONFIG}.tmp" "${FINAL_CONFIG}"

log_info "haproxy.cfg generated successfully."

# -----------------------------------------------------------------------------
# 3. CERTIFICATE LOGIC (Self-Signed & Let's Encrypt)
# -----------------------------------------------------------------------------

# Generate self-signed certificate if it doesn't exist
if [ ! -f "${DEFAULT_PEM}" ]; then
    log_info "Generating self-signed certificate..."
    
    # Use temporary files for keys/certs
    TEMP_DIR=/tmp
    KEY=${TEMP_DIR}/haproxy_key.pem
    CERT=${TEMP_DIR}/haproxy_cert.pem
    SUBJ="/C=US/ST=somewhere/L=someplace/O=haproxy/OU=haproxy/CN=haproxy.selfsigned.invalid"
    
    # Generate key and CSR without passwords and combine them in a single pipe (faster/cleaner)
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "${KEY}" -out "${CERT}" \
        -subj "${SUBJ}" &>/dev/null
    
    cat "${CERT}" "${KEY}" > "${DEFAULT_PEM}"
    rm -f "${KEY}" "${CERT}"
    log_info "Default self-signed certificate created."
fi

# Check for existing Certbot setup and run if necessary
# Replaces bashio::config.has_value 'cert_domain'
if [ -n "${CERT_DOMAIN}" ]; then
    FULLCHAIN_PATH="${CERTBOT_CERT_PATH}/fullchain.pem"
    
    # Check if certificate exists (for renewal check or initial skip)
    if [ -f "${FULLCHAIN_PATH}" ]; then
        log_info "Existing certificate found. HAProxy will handle renewal."
    
    # Initial request logic
    # Replaces bashio::var.is_empty "${CERT_EMAIL}"
    elif [ -z "${CERT_EMAIL}" ]; then
        exit_nok "Certbot is enabled via CONFIG_CERT_DOMAIN but CONFIG_CERT_EMAIL is missing."
    
    else
        log_warn "No existing certificate found. Starting HAProxy temporarily for initial validation..."
        
        # Ensure Certbot directories are ready
        mkdir -p "${CERT_PERSISTENT_DIR}/work" "${CERT_PERSISTENT_DIR}/log"
        
        # 1. Start HAProxy in the background for ACME challenge
        /usr/local/sbin/haproxy -f "${FINAL_CONFIG}" -D -p "${HAPROXY_PID_FILE}" &
        
        # 2. Wait for PID file creation (max 10s)
        for i in {1..10}; do
            [ -f "${HAPROXY_PID_FILE}" ] && break
            sleep 1
        done

        # 3. Process HAProxy PID
        if [ -f "${HAPROXY_PID_FILE}" ]; then
            HAPROXY_PID=$(cat "${HAPROXY_PID_FILE}")
        else
            log_error "HAProxy failed to start for Certbot validation."
            exit 1 # Exit script if HAProxy failed to start for the critical task
        fi
        
        # 4. Run Certbot
        log_info "Attempting to obtain certificate for domain: ${CERT_DOMAIN}..."
        if /usr/bin/certbot-certonly \
            --config-dir "${CERT_PERSISTENT_DIR}" \
            --work-dir "${CERT_PERSISTENT_DIR}/work" \
            --logs-dir "${CERT_PERSISTENT_DIR}/log" \
            --email "${CERT_EMAIL}" \
            --domains "${CERT_DOMAIN}" --non-interactive --webroot --webroot-path /var/www/html; then
            
            log_info "Certificate successfully obtained! Running refresh..."
            # NOTE: haproxy-refresh is assumed to be an external script/function available
            # in the execution environment that reloads HAProxy (e.g., `kill -USR2 $(cat /var/run/haproxy.pid)`).
            haproxy-refresh
        else
            log_error "Certbot certificate request failed. HAProxy will use self-signed."
        fi
        
        # 5. Stop the temporary HAProxy instance
        log_info "Stopping temporary HAProxy (PID ${HAPROXY_PID})."
        kill "${HAPROXY_PID}" 2>/dev/null || log_warn "Temporary HAProxy was already stopped."
    fi
fi

# -----------------------------------------------------------------------------
# 4. NETWORKING (IPTABLES / TC SETUP)
# -----------------------------------------------------------------------------

# Find the IP address more reliably
IP=$(ip route get 1.1.1.1 | awk '/src/ {print $7}' | head -n 1)

if [ -n "$IP" ]; then
    log_info "Setting up IPTABLES/TC for TPROXY/loopback traffic on IP: ${IP}"

    # --- IPTABLES: only insert MARK rule if it doesn't already exist ---
    if ! /usr/sbin/iptables -t mangle -C OUTPUT -p tcp -s "${IP}" --syn -j MARK --set-mark 1 2>/dev/null; then
        /usr/sbin/iptables -t mangle -I OUTPUT -p tcp -s "${IP}" --syn -j MARK --set-mark 1 \
            || log_warn "Failed to add iptables mangle OUTPUT rule for IP ${IP}"
    else
        log_info "IPTABLES mangle OUTPUT rule for IP ${IP} already present."
    fi

    # --- TC qdisc root: add only if not already there ---
    if ! tc qdisc show dev lo | grep -q "handle 1: root prio"; then
        tc qdisc add dev lo root handle 1: prio bands 4 \
            || log_warn "TC qdisc add dev lo root failed."
    else
        log_info "TC root qdisc on lo already present."
    fi

    # --- TC child qdiscs 1:1, 1:2, 1:3 (10:,20:,30:) ---
    if ! tc qdisc show dev lo | grep -q "parent 1:1 handle 10:"; then
        tc qdisc add dev lo parent 1:1 handle 10: pfifo limit 1000 \
            || log_warn "TC qdisc add 1:1 failed."
    fi

    if ! tc qdisc show dev lo | grep -q "parent 1:2 handle 20:"; then
        tc qdisc add dev lo parent 1:2 handle 20: pfifo limit 1000 \
            || log_warn "TC qdisc add 1:2 failed."
    fi

    if ! tc qdisc show dev lo | grep -q "parent 1:3 handle 30:"; then
        tc qdisc add dev lo parent 1:3 handle 30: pfifo limit 1000 \
            || log_warn "TC qdisc add 1:3 failed."
    fi

    # --- nl-qdisc plug 40: on parent 1:4 ---
    # Only create the plug if it doesn't already exist
    if command -v nl-qdisc-list >/dev/null 2>&1; then
        if ! nl-qdisc-list --dev=lo 2>/dev/null | grep -q "id 40:"; then
            nl-qdisc-add --dev=lo --parent=1:4 --id=40: plug --limit 33554432 \
                || log_warn "nl-qdisc-add plug failed."
        else
            log_info "nl-qdisc plug 40: already present on lo."
        fi
    else
        # Fallback: try to add, ignore 'Object exists'
        nl-qdisc-add --dev=lo --parent=1:4 --id=40: plug --limit 33554432 \
            || log_warn "nl-qdisc-add plug (no nl-qdisc-list available) failed."
    fi

    # Always ensure the plug is in release-indefinite mode
    nl-qdisc-add --dev=lo --parent=1:4 --id=40: --update plug --release-indefinite \
        || log_warn "nl-qdisc-add update failed."

    # --- TC filter: only add fw filter once ---
    if ! tc filter show dev lo parent 1:0 2>/dev/null | grep -q "fw classid 1:4"; then
        tc filter add dev lo protocol ip parent 1:0 prio 1 handle 1 fw classid 1:4 \
            || log_warn "TC filter add failed."
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
