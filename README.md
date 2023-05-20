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

## DIY

### Pull the Docker Image
You can build the Docker image (check the files inside `docker-stack`) or you can pull it from the Dockerhub register:
```
docker pull lemariva/haproxy-certbot:1.1.2-SNAPSHOT
```
To start the service, `docker-compose` must be installed. Otherwise, you need to configure all the variables and settings that you can find inside the `docker-compose.yml` file.

### Configure the Docker Service
But, before starting the service, edit `SERVICE_IP` and `PORT_IP` variables inside the file `docker-compose.yml`. Both should point to the service that you are forwarding. In my case, that is:
```
SERVICE_IP: 192.168.178.161
SERVICE_PORT: 8123
```
The IP `192.168.178.161` and port `8123` points to my Raspberry Pi address and the standard port of HA, respectively.

Then, you can start the service by typing the following:
```
cd orchestration
docker-compose up -d
```

### Configure HA
If you are running HA with version greater than v2021.7.0, you will get a "400 Bad Request" error when I tried to access HA via the HTTP/HTTPS address. A breaking change was added to this version and if you are running a proxy you need to add to the `configuration.yaml` the following:
```
# proxy
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - <<PROXY_IP>>
```
If your proxy is running on another machine, you need to change `<<PROXY_IP>>` with the IP address of that machine. But, if you are running the proxy on the same machine that HA is running, you need to change `<<PROXY_IP>>` with the Docker internal IP of the container. You can get that by typing the following:
```
docker container inspect `docker ps -aqf "name=haproxy-certbot"` | grep "\"IPAddress\": \"1"
```
Note: this works if you didn't change the name to the container (`LOAD_BALANCER_NAME`) inside the `.env` file. Otherwise, you need to change that.
You get something like this:
```
pi@homeassistant:~ $ docker container inspect `docker ps -aqf "name=haproxy-certbot"` | grep "\"IPAddress\": \"1"
                    "IPAddress": "172.26.0.2",
```
The `172.26.0.2` is the IP address that you need.

### Get the first certificate
To get a certificate from Let's Encrypt, you need to forward the port `80` and `443` of your computer to the Internet and you need a URL pointing to your router (basically a domain name). Internet providers usually change the IP address that you get every 24 hours. Thus, you need to get a dynamic DNS service. I use [NoIP](https://www.noip.com?fpr=y842j), it's free but you need to confirm your host every 30 days (no big deal). If you are thinking of buying a subscription, you can get a 5 dollars discount using the promo code `REFER5`, After opening the ports on your router and getting a domain name thats point to your router, you can get the first certificate from Let's Encrypt. To do that, you need to get inside the Docker container using:
```
docker container exec -it `docker ps -aqf "name=haproxy-certbot"` /bin/bash
```
and run the following commands:
```
/usr/bin/certbot certonly -c /usr/local/etc/letsencrypt/cli.ini --agree-tos --email <<YOUR_EMAIL>> --domains <<YOUR_DOMAIN>>

haproxy-refresh
```
Replace `<<YOUR_EMAIL>>` and `<<YOUR_DOMAIN>>` with your valid email address and the domain that points to your router. If everything goes as planned, you will get a valid SSL certificate for your HA system.

Then, you can integrate your HA to e.g. Google Home Assistant following the steps in [this tutorial](https://www.home-assistant.io/integrations/google_assistant/).

