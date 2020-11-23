# Client bootstrap service

## Webserver (nginx) installation

After having installed **nginx**, follow these steps to expose the endpoints needed for client bootstrapping:

- copy the `nginx/scion` configuration to `/etc/nginx/sites-available` and
 enable it by creating a link that points to `/etc/nginx/sites-available/scion` in `/etc/nginx/sites-enabled`),
- create a link to the topology to expose in `/srv/http/scion/discovery/v1/topology.json`, and
- create a link to the folder containing the certificates to serve in `/srv/http/scion/discovery/v1/certs/`.

### Check the webserver

You can test that the webserver is working with:

- `curl ${SERVER_IP}:8041/scion/discovery/v1/topology.json`, and
- `curl ${SERVER_IP}:8041/scion/discovery/v1/certs/`

The former should return the topology of the AS.
The latter should return a list of certificate files.

## Systemd

---
title: Setup automatic endhost configuration
parent: Configuration
nav_order: 40
---

## Setup automatic endhost configuration

To have endhosts automatically join the SCION AS rather than configure the
endhost manually, you can deploy the bootstrapping service.

### Deploy the Discovery Service

The Discovery Service is a static HTTP server hosting the `topology.json` file.
We describe a sample setup using nginx but any webserver with the same URL paths
will work.

Install nginx on the system you want to use as the discovery server:

```shell
sudo apt-get install nginx
```

Put the following configuration into `/etc/nginx/nginx.conf`:

```nginx
user www-data www-data;
worker_processes  auto;
events {
    worker_connections  1024;
}
http {
    include       mime.types;
    access_log  /var/log/nginx/access.log;
    error_log   /var/log/nginx/error.log;
    server_tokens off;
    types_hash_max_size 4096;
    server_names_hash_bucket_size 128;
    keepalive_requests 32;
    keepalive_timeout 60s;
    server {
        listen      *:8041;
        listen      [::]:8041;
        location / {
            root /srv/http;
            autoindex on;
        }
    }
}
```

Start the nginx webserver:

```shell
sudo systemctl enable --now nginx
```

Put the `topology.json` file of your AS into
`/srv/http/discovery/v1/static/endhost.json`

Check that the topology can be fetched by accessing
`http://<yourdiscoveryserver>:8041/discovery/v1/static/endhost.json`. This
should serve your topology file.

### Configure a Discovery Mechanism

Choose at least one of the described options:

#### DHCP configuration

Configure your local DHCP server to provide clients with the IP address of your
discovery service as option 72 "Default WWW server". The concrete configuration
depends on your DHCP server. For `dnsmasq` add the following line to
`/etc/dnsmasq.conf`: `dhcp-option=72,<yourdiscoveryserverIP>`

#### mDNS configuration

Install an mDNS daemon on your machine:

```shell
sudo apt-get install avahi-daemon
```

Put the configuration to `/etc/avahi/services/sciondiscovery.xml`:

```xml
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">%h</name>
  <service>
    <type>_sciondiscovery._tcp</type>
    <port>8041</port>
  </service>
</service-group>
```

```shell
sudo systemctl enable --now avahi-daemon
```

#### DNS Configuration

Configure your DNS domain (if you have one) to contain the following records:

Using DNS SD:

```dns
_sciondiscovery._tcp.<yourdomain> IN SRV 10 10 8041 <yourdiscoveryserver>
<yourdiscoveryserver> IN A <yourdiscoveryserverIP>
```

OR using DNS S-NAPTR:

```dns
<yourdomain> IN NAPTR 10 10 "a" "x-sciondiscovery:tcp" <yourdiscoveryserver>
<yourdiscoveryserver> IN A <yourdiscoveryserverIP>
```

### Configure the endhost

On the endhost install and enable the following. Replace `ens1` with your actual
network interface.

```shell
sudo apt-get install scion-bootstrapper
sudo systemctl enable --now scion-dispatcher.service
sudo systemctl enable --now scion-bootstrapper@ens1.service
sudo systemctl enable --now scion-daemon-bootstrap@ens1.service
sudo systemctl enable --now scionlab.target
