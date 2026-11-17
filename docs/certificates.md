<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Certificates

*Services → Certificates* gets TLS certificates from Let's Encrypt (ACME). The CA
checks each domain of the certificate with one of two challenges:

- **HTTP-01**: the CA fetches a token from
  `http://<domain>/.well-known/acme-challenge/`, so every domain must reach the
  firewall from the Internet. See below.
- **DNS-01**: the firewall puts a TXT record at `_acme-challenge.<domain>`, so the
  domains need not be reachable at all: internal names, and wildcards
  (`*.example.com`), work. See [DNS-01](#dns-01).

With HTTP-01:

- Every domain must resolve (A, and AAAA if it has one) to an address of the
  certificate's *Interface*, the WAN say. A dynamic DNS zone (DNS, *New dynamic zone*)
  can keep those records.
- The firewall opens TCP port 80 on the certificate's interface only while it
  answers a challenge (the auto rule *acme http-01*); port 80 is closed the rest of
  the time. A port forward (DNAT) of port 80
  on that interface takes the CA's requests elsewhere: remove it, or get the
  certificate on the server behind it.
- A certificate is ordered when it is deployed, when its SANs, common name, CA or key type
  change, and renewed when two thirds of its lifetime have passed (30 days before the
  end of a 90-day one). A failed order is tried again after 10 minutes, then after
  twice as long each time, up to 12 hours.
- The *State* column shows until when the certificate is valid, and the last
  error.
- Try *Let's Encrypt staging* first: its certificates are not trusted, but its rate
  limits are far higher than production's (5 failed validations per hour per domain).

### DNS-01

A DNS-01 certificate names a *DNS update client* (*Services → DNS update*) of the
same virtual firewall, whose provider (RFC 2136 or a DNS hosting provider's API)
and credentials write the TXT records, in the client's zone. Its records, interface
and switch don't matter here: a client kept only for certificates can be disabled
and have no records. While a client is used by a certificate, it can't be deleted.

- **Names in another zone (CNAME).** The record is put where
  `_acme-challenge.<domain>` leads: a CNAME there (or a chain of them) is followed,
  as the CA follows it. So the zones of your internal names need no API or
  credentials on the firewall; one CNAME per name, made once, points into a zone
  the client can write:

  ```
  _acme-challenge.nas.corp.example.com.  CNAME  nas.acme.example.net.
  _acme-challenge.corp.example.com.      CNAME  corp.acme.example.net.   ; also *.corp.example.com
  ```

  with the DNS update client's zone `acme.example.net`. Without a CNAME the name
  `_acme-challenge.<domain>` itself must be in the client's zone. A name that leads
  elsewhere fails the order with a message naming where the CNAME leads.
- The CNAMEs are looked up through the firewall host's resolvers
  (`/etc/resolv.conf`), and the CA looks them up in public DNS: both must see them.
  So must Let's Encrypt see the TXT record, so the client's zone must be public.
- A TXT value is added to the name's records and removed when the order is done,
  so `example.com` and `*.example.com`, which share `_acme-challenge.example.com`,
  can be in one certificate. The firewall waits up to 5 minutes for the zone's
  nameservers to have the record before the CA checks it.
- An RFC 2136 nameserver is reached from the virtual firewall, through its routes and
  rules, as the client's updates are; a provider's API from the firewall host.

### The certificate store

The *Certificate store* tab shows the virtual firewall's certificates as a tree by
their certification path: each certificate under the CA that signed it, from the
root CA down (*ISRG Root X1* → *R11* → your Let's Encrypt certificate; a CA of the
firewall → the certificates it signed), so the path a client checks can be seen at
a glance. The path is read from each certificate's chain; an issuer that is not a
certificate of the virtual firewall itself is shown by its name, and a certificate
not got yet is at the top. The arrow before an issuer folds it.

### Imported certificates

A certificate from another CA is imported with its key: *Import certificate* on the
*Certificate store* tab takes PEM files (the certificate, its intermediates and the private key;
one file may hold them all) or pasted PEM. The key must match the certificate; the
SANs and common name are read from it. It is written to the same directory at the
next commit, has no challenge and opens no port, and is never renewed: its state
turns *expired* once past its end. To replace it, edit it on the *ACME certificates* tab and
paste the new certificate (and a new key, unless it reuses the old one). The key is
never shown again, and the deployment history keeps it redacted.

### Certificate authorities

A certificate authority (CA) belongs to the **firewall**, not to a virtual firewall:
the *Certificate authorities* tab shows the firewall's CAs (`certificate-authority`
in the CLI). A CA stays in Portitor's configuration, key included (on both firewalls of
a cluster, with the rest of it), and is not deployed: the certificates it signs
carry it in their chain. Global admins manage CAs.

- **New CA** makes one (a common name, the key type, ten years by default), or
  imports an existing CA with its key (*Import a CA with its key*), which then signs
  too. A CA can't be added as a certificate (of a virtual firewall or the host).
- **Export** on its row downloads its certificate (PEM or DER, without the key).
  Add it to the trust store of the hosts that should trust what it signs, e.g.
  `/usr/local/share/ca-certificates/<name>.crt` and `update-ca-certificates` on
  Debian, or *Trusted Root Certification Authorities* on Windows.
- **Sign for &lt;VF&gt;** on its row opens *Create certificate* (below) for the
  virtual firewall selected in the top bar, signed by that CA.

Deleting a CA leaves the certificates it signed as they are.

### Created certificates

*Create certificate* on the *Certificate store* tab makes a new key and a server certificate for
it in the selected virtual firewall (or host): *Signed by* one of the firewall's
certificate authorities (global admins only) or self-signed, for the SANs you give (DNS
names, wildcards and IP addresses), valid for the days you give (825 by default,
the most Apple's systems accept), but never past its CA's end. Its chain holds its CA after it. It is
then an imported certificate like any other: deployed at the next commit, never
renewed, so make a new one before it ends.

### The GUI's own certificate

The GUI can use one of these certificates instead of its self-signed one: choose it
under *Settings → Portitor web*. It takes effect at once, and a renewed certificate is
used without a restart. The certificate's name must be the name you browse to.

Behind portitor-manager, the browser sees portitor-manager's certificate instead.

## ACME proxy

The *ACME proxy* tab of *Services → Certificates* is an ACME server for the hosts
behind the firewall. A host runs its usual ACME client (certbot, Caddy, Traefik,
lego, acme.sh) with the proxy's directory URL instead of Let's Encrypt's. The client proves control of a name over
the internal network with HTTP-01, and the firewall gets the certificate from Let's
Encrypt. Each policy says how Let's Encrypt checks its names for the firewall:

- **DNS-01**, through a DNS update client. Only the firewall holds the DNS
  credentials, and the hosts need not be reachable from the Internet.
- **HTTP-01**, answered by the firewall itself on port 80 of an interface (the WAN),
  as for an [HTTP-01 certificate](#certificates). The names must resolve to that
  interface's address from the Internet, and port 80 there must not be forwarded to
  another host. Inside, the names may resolve to the hosts themselves (split DNS).
  No DNS credentials are needed, and the hosts still need not be reachable.

1. For DNS-01, make a DNS update client (*Services → DNS update*) whose zone holds
   the names' `_acme-challenge` records, or their CNAME targets, as for a
   [DNS-01 certificate](#dns-01).
2. Add a policy: the names (`nas.lan.example.com`, or `*.lan.example.com` for any
   name below it), the clients (prefixes, or hosts and prefixes by name; empty is
   any), the upstream challenge, and the DNS update client (DNS-01) or the
   interface (HTTP-01).
3. Turn the proxy on, pick the interfaces it answers on, and commit. Its status
   shows the directory URLs, such as `https://192.168.1.1:8555/directory`.

When a client orders a name:

- The name must be allowed from the client's address by a policy (tried in name
  order; the first that matches is used). Otherwise the order is refused.
- The firewall resolves the name in the virtual firewall (its own DNS, if the
  firewall serves it), and every address must be in that policy's clients. It then
  fetches `http://<name>/.well-known/acme-challenge/<token>` from the virtual
  firewall. It does not follow redirects, so the client must answer on port 80
  itself, as certbot's standalone and webroot modes, Caddy and Traefik do.
- As soon as the order is accepted, the firewall has Let's Encrypt check the names
  with the policy's challenge, while the client answers its own challenge. The
  names of one order must use the same upstream challenge; an order mixing DNS-01
  and HTTP-01 names fails, and the client should order them separately. When the client then
  sends its CSR, Let's Encrypt reuses those checks, so the certificate comes back
  within seconds. This matters because some clients, such as Traefik and lego, wait
  only 30 seconds for it.
- The certificate is for the client's own key: the firewall never sees it. The
  client renews as usual. Let's Encrypt's rate limits apply to the names as always.

Wildcard certificates can't be ordered through the proxy, since HTTP-01 can't check
them; get those as a [DNS-01 certificate](#dns-01) on the firewall.

The proxy listens with HTTPS. Its certificate is either one of the virtual
firewall's certificates (from *Certificates*), which clients trust as they are, or a
self-signed one the firewall makes, for the serving interfaces' addresses. That one
must be downloaded from the status and given to the clients:

```sh
REQUESTS_CA_BUNDLE=/etc/ssl/acme-proxy.pem certbot certonly --standalone \
  --server https://192.168.1.1:8555/directory -d nas.lan.example.com
LEGO_CA_CERTIFICATES=/etc/ssl/acme-proxy.pem lego --server https://192.168.1.1:8555/directory ...
```

Traefik takes `LEGO_CA_CERTIFICATES` too, and Caddy takes `acme_ca_root`. The
*Issued* list shows the latest certificates, with the client, names and the error of
a failed order. The clients' ACME accounts are kept by the firewall; orders in
progress are lost when the firewall restarts, and the client orders again.

