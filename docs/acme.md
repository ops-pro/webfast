# Automatic certificates (ACME)

How a site gets its certificate without `tls <cert> <key>` (`src/acme/`, cargo feature `acme`, on
by default). Written as the decision before the code; kept as the description of it.

## The decision

**A site with a host name on the HTTPS port and no `tls` files is managed:** its certificate is
obtained from an ACME certificate authority (Let's Encrypt unless `acme_ca` says otherwise) and
renewed, as Caddy's automatic HTTPS does. `auto_https off` or `disable_certs` turns it off, and
then a site with a host name on the HTTPS port is an error, as before. A host that is an IP
address, `localhost`, or a wildcard (`*.example.com` needs DNS-01, which is not done) is not
managed: it needs `tls` files.

**HTTP to HTTPS:** for every managed host a server on `http_port` answers with 308 to the same URL
over `https`, unless `auto_https disable_redirects` or a site of the Caddyfile already listens
there for that host. The ACME challenge path is answered before any route, on any port, so a
redirect never catches it.

**Challenges:** HTTP-01 when the server listens on `http_port` for the host, else TLS-ALPN-01.
Nothing is written to the site: the HTTP-01 answer (`/.well-known/acme-challenge/<token>`) is a
request check (`src/extensions.rs`) that answers from a map of pending tokens, composed before
the other checks and present only when a host is managed — the request path's first bytes
compared, nothing more, for every other request; the TLS-ALPN-01 answer is a certificate the
resolver (`src/tls.rs`) hands out for a handshake offering `acme-tls/1` for a name with a
pending challenge. Both maps are empty except while an order runs. Validation is not watched in
the log: the order is polled at the CA, as the protocol has it.

**The work is one background thread** (`Worker`, `webfast-acme`, its own runtime for the ACME
client): at start, every managed host whose certificate is missing or due is ordered; from then
on a check an hour renews what is due. Nothing of it runs on a request or a connection. One order
at a time, so a Caddyfile with many hosts does not burst the CA.

**Renewal is due at two thirds of the certificate's life** (Caddy's default; a 90-day certificate
at 60 days, a 6-day one at 4), and the server starts serving the new certificate as soon as it is
written: the resolver re-reads the files when told, as it does when they change on disk.

**Storage:** `WEB_ACME_DIR` (`/data/acme`; the image has `/data` for the user it runs as), a
directory per CA: `account.json` (the account's key and URL), `certs/<host>/cert.pem` and
`key.pem` (0600). The site's certificate files are these paths: a managed site is a `tls` site
whose files the server writes itself, and until they exist the host gets no certificate (a
handshake for it ends, as for a name no site serves). A file that is broken keeps the old
certificate, as for any `tls` file.

**A failure changes nothing:** the certificate on disk stays in use, the order is tried again
with a back-off (1 minute doubling to 1 day) and logged at warn, then at debug. The CA's rate
limits (Let's Encrypt: 5 certificates per set of names per week, 300 orders per account per 3
hours) are the one thing the back-off protects: an order is never repeated within a minute, and a
certificate that is valid is never ordered again.

**Several replicas:** each obtains its own certificate for its own directory. A shared volume
would need a lock, which this does not take; it is not a cluster certificate store.

**Tests get certificates from a test CA only:** Pebble (Let's Encrypt's test server) in Docker,
also in CI; never from Let's Encrypt's production, and not from its staging either (it needs a
public name).

## In the Caddyfile

```
{
	email admin@example.com
	# acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
	# acme_ca_root /etc/webfast/pebble.minica.pem
}
example.com {
	root * /srv
	file_server
}
api.example.com {
	tls ops@example.com
	reverse_proxy app:8080
}
```

Read: the global options `email`, `acme_ca`, `acme_ca_root`, `auto_https off | disable_redirects
| disable_certs`; the site's `tls <email>`. Not read: `tls internal` (a local CA), `tls { dns … }`
(DNS-01 and wildcards), `tls { issuer … }`, `on_demand_tls`, `acme_dns`, `acme_eab`, `cert_issuer`,
`default_sni`; a `tls` block of any kind.

Outside the Caddyfile: `WEB_ACME_DIR`.
