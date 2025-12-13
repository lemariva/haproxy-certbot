# HAPROXY and Let's Encrypt

HAProxy is a free, very fast, and reliable reverse-proxy offering high availability, load balancing, and proxying for TCP and HTTP-based applications. 
This repository combines HAProxy and Let's Encrypt to provide high-performance SSL termination, allowing you to encrypt and decrypt traffic to your HTTP-based application. Let's Encrypt is a certification authority that provides simple and free SSL certificates. The CA is embedded in all relevant browsers so that you can secure your websites with Let's Encrypt. And all at no cost.

Let's start with some explanation about how HTTPS works: The encryption and security functionalities for HTTP are implemented through the Transport Layer Security (TLS) protocol. TLS defines a standard way to secure any network communication channel. The idea is that when a client (browser, application, etc.) establishes a connection with a server and requests an encrypted connection, the server responds with its SSL certificate. This certificate acts as an identification for the server (includes the name of the server and the domain) and is signed by a certificate authority (CA). If the client knows and trusts the CA, they can confirm that the certificate signature comes from the entity, and then they can be sure that the server is legitimate.

After verifying the certificate, the client creates an encryption key to use for communicating with the server. This key is sent securely to the server (encrypted with the public key included with the server's certificate). The server, which has the private key (that corresponds to the public key), can decrypt the packet and obtain the key. From this point on, all traffic is encrypted with the key that only the client and server know.

Therefore, we need two items:

* a server certificate, which includes a public key and is signed by a CA,
* and a private key that goes with the public key included in the certificate.

To request a certificate from a CA, the entity is going to verify that you are in control of your server and domain. This verification depends on the CA, and if the server passes the verification, then the CA will issue a certificate for the server with its signature that you can install. This certificate lasts for a year. However, most CAs charge money for these certificates. But, in recent years there are more and more CAs that offer them for free. The most popular is Let's Encrypt.

Therefore, you can use this Docker image to add an SSL layer to your HTTP-based applications. The following steps are for Home Assistant (HA).

## Usage

### Docker Configure & Run
You can run the container using Docker Compose. Below is an example configuration:

```yaml
version: "3.8"

services:
  haproxy:
    image: lemariva/haproxy-certbot:latest
    container_name: haproxy_proxy
    restart: always
    
    # Required for TPROXY/IPTABLES setup
    network_mode: "host" 
    cap_add:
      - NET_ADMIN
      - NET_RAW

    volumes:
      # Persistent directory for Let's Encrypt certificates
      - ./config/le_certs:/addon_config/le_certs
      # Data directory for generated haproxy.cfg
      - ./data:/data 
      # Mount /var/run to access haproxy_role file (managed by Keepalived or manually)
      - /var/run:/var/run 

    environment:
      # --- Core Configuration ---
      CONFIG_DATA_PATH: "data"
      CONFIG_STATS_USER: "haproxy_admin"
      CONFIG_STATS_PASSWORD: "stats_password"
      CONFIG_HA_PRIMARY_IP: "192.168.1.10"   # IP of the backend service (e.g. Home Assistant)
      CONFIG_HA_SECONDARY_IP: "192.168.1.11" # Backup IP (optional/redundant)
      CONFIG_HA_PORT: "8123"                 # Port of the backend service
      CONFIG_LOG_LEVEL: "info"

      # --- Certbot Configuration ---
      CONFIG_CERT_DOMAIN: "home.example.com"
      CONFIG_CERT_EMAIL: "admin@example.com"
      
      # --- Mapped Ports ---
      # These inform the HAProxy configuration template
      MAPPED_HOST_PORT_80: "80"
      MAPPED_HOST_PORT_443: "443"
      MAPPED_HOST_PORT_9999: "9999"
```

### Configuration Variables

| Variable | Description |
|----------|-------------|
| `CONFIG_DATA_PATH` | Path inside the container for storing data (should match a volume). |
| `CONFIG_STATS_USER` | Username for the HAProxy stats page. |
| `CONFIG_STATS_PASSWORD` | Password for the HAProxy stats page. |
| `CONFIG_HA_PRIMARY_IP` | Primary IP address of the backend service to load balance to. |
| `CONFIG_HA_SECONDARY_IP`| Secondary IP address of the backend service (for redundancy). |
| `CONFIG_HA_PORT` | Port of the backend service. |
| `CONFIG_CERT_DOMAIN` | The domain name for the SSL certificate. |
| `CONFIG_CERT_EMAIL` | Email address for Let's Encrypt registration. |
| `MAPPED_HOST_PORT_80` | External HTTP port (usually 80). |
| `MAPPED_HOST_PORT_443` | External HTTPS port (usually 443). |
| `MAPPED_HOST_PORT_9999`| External Stats port. |

### Home Assistant Configuration
If you are using this with Home Assistant, you must configure it to trust the proxy's IP address (the `X-Forwarded-For` header). Add the following to your `configuration.yaml`:

```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 172.16.0.0/12  # Private Docker IP range, OR specific container IP
    - 127.0.0.1      # Localhost
```
*Note: Adjust the `trusted_proxies` IP range to match your Docker network or the specific IP of the HAProxy container.*

## High Availability & Certificates

This image is designed to work in a High Availability (HA) environment (e.g., using Keepalived).

- **Master/Backup Role**: The container checks the file `/var/run/haproxy_role` to determine its state. 
    - If the file contains `MASTER`, the container **enables Certbot** to request and renew certificates.
    - If it contains `BACKUP` (or the file is missing), Certbot operations are skipped, and the container expects valid certificates to be present in the shared persistent volume (`/addon_config/le_certs`).

> **Note**: For a standalone single-node setup, you must ensure this role file exists and contains `MASTER`, or the container will not generate certificates.

## Networking (TPROXY)
To support Transparent Proxying (preserving client IP addresses), the container requires:
1. `network_mode: "host"`
2. `NET_ADMIN` and `NET_RAW` capabilities.
3. iptables and iproute2 (installed in the image).
The `start.sh` script automatically configures the necessary `iptables` rules and `tc` qdiscs on container startup.

