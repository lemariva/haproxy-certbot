#========= Stage 1: Build HAProxy =========
# This stage downloads build dependencies and compiles HAProxy
FROM alpine:3.22 AS dependencies_and_build

ARG HAPROXY_MAJOR=3.2
ARG HAPROXY_VERSION=3.2.7

# Install all build-time dependencies in a single layer
RUN set -eux; \
    apk add --no-cache --virtual .build-deps \
        gcc \
        libc-dev \
        linux-headers \
        lua5.4-dev \
        make \
        openssl-dev \
        pcre2-dev \
        readline-dev \
        tar \
        wget

# Download, compile, and install HAProxy
RUN set -eux; \
    \
    wget -O haproxy.tar.gz "http://www.haproxy.org/download/${HAPROXY_MAJOR}/src/haproxy-${HAPROXY_VERSION}.tar.gz"; \
    mkdir -p /usr/src/haproxy; \
    tar -xzf haproxy.tar.gz -C /usr/src/haproxy --strip-components=1; \
    rm haproxy.tar.gz; \
    \
    makeOpts=' \
        TARGET=linux-musl \
        USE_GETADDRINFO=1 \
        USE_LUA=1 LUA_INC=/usr/include/lua5.4 LUA_LIB=/usr/lib/lua5.4 \
        USE_OPENSSL=1 \
        USE_PCRE2=1 USE_PCRE2_JIT=1 \
        USE_PROMEX=1 \
        EXTRA_OBJS="" \
    '; \
    \
    nproc="$(getconf _NPROCESSORS_ONLN)"; \
    eval "make -C /usr/src/haproxy -j '$nproc' all $makeOpts"; \
    eval "make -C /usr/src/haproxy install-bin $makeOpts"; \
    \
    # Create a directory for error files in the build stage
    mkdir -p /usr/local/etc/haproxy/errors; \
    cp -R /usr/src/haproxy/examples/errorfiles /usr/local/etc/haproxy/errors; \
    rm -rf /usr/src/haproxy; \
    \
# Smoke test the build
    haproxy -v


#========= Stage 2: Final Release Image =========
# This stage builds the final, lean image for the add-on
FROM alpine:3.22 AS release

# Add build-time ARGs and LABELs for metadata
ARG VCS_REF=`git rev-parse --short HEAD`
ARG SEMVER_REVISION=1.1.0
ARG BUILD_DATE=`$(date -u +"%Y-%m-%dT%H:%M:%SZ")`

LABEL org.label-schema.build-date=${BUILD_DATE} \
      org.label-schema.vcs-url="https://github.com/lemariva/hassio-haproxy-certbot.git" \
      org.label-schema.name="HAProxy Certbot" \
      org.label-schema.description="haproxy proxy with letsencrypt certbot for https" \
      org.label-schema.vcs-ref=${VCS_REF} \
      org.label-schema.version=${SEMVER_REVISION} \
      org.label-schema.vendor="LeMaRiva|Tech"

# Create the non-root user for HAProxy
RUN set -eux; \
    addgroup --gid 99 --system haproxy; \
    adduser \
        --disabled-password \
        --home /var/lib/haproxy \
        --ingroup haproxy \
        --no-create-home \
        --system \
        --uid 99 \
        haproxy

# Install all runtime dependencies in a single layer
# This includes HAProxy's deps (lua, pcre2) and the add-on's deps
RUN apk add --no-cache --update \
    supervisor \
    libnl3-cli \
    net-tools \
    iproute2 \
    certbot \
    openssl \
    iptables \
    ip6tables \
    lua5.4-libs \
    pcre2 \
    ca-certificates \
    curl \
    bash \
    && rm -rf /var/cache/apk/*

# Create all required directories in one layer
RUN mkdir -p /var/log/supervisor \
    && mkdir -p /usr/local/etc/haproxy/certs.d \
    && mkdir -p /usr/local/etc/letsencrypt \
    && mkdir -p /config

# Copy compiled artifacts from the build stage
COPY --from=dependencies_and_build /usr/local/sbin/haproxy /usr/local/sbin/haproxy
COPY --from=dependencies_and_build /usr/local/etc/haproxy/errors /usr/local/etc/haproxy/errors

# Copy configuration files and scripts
COPY resources/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY haproxy/config/haproxy.cfg.template /app/haproxy.cfg.template
COPY resources/certbot /etc/cron.d/certbot
COPY resources/cli.ini /usr/local/etc/letsencrypt/cli.ini
COPY resources/haproxy-refresh /usr/bin/haproxy-refresh
COPY resources/haproxy-restart /usr/bin/haproxy-restart
COPY resources/haproxy-check /usr/bin/haproxy-check
COPY resources/certbot-certonly /usr/bin/certbot-certonly
COPY resources/certbot-renew /usr/bin/certbot-renew
COPY resources/start.sh /start.sh

# Set permissions and install cron in one layer
RUN chmod +x /usr/bin/haproxy-refresh /usr/bin/haproxy-restart \
        /usr/bin/haproxy-check /usr/bin/certbot-certonly /usr/bin/certbot-renew \
        /start.sh \
    && crontab /etc/cron.d/certbot

# Add the requested HEALTHCHECK (assumes HAProxy stats are on port 8099)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:9999/stats || exit 1

# Expose ports and set volumes
EXPOSE 443 80 9999
VOLUME [/etc/letsencrypt/ /usr/local/etc/haproxy/certs.d/]

# Set the entrypoint
CMD ["/start.sh"]