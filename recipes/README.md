# Recipes

Complete configurations for common setups. Every Caddyfile here is loaded by the tests
([`tests/recipes.rs`](../tests/recipes.rs)), and the static site and the single-page app are also
served and asked a few requests, so they stay valid as webfast changes.

| Recipe                       | For                                                                                               |
| ---------------------------- | ------------------------------------------------------------------------------------------------- |
| [static-site](static-site)   | a site built ahead of time: clean URLs, precompressed siblings, long caching for hashed assets    |
| [spa](spa)                   | a single-page app: its files, and `index.html` for every other path                               |
| [app-behind](app-behind)     | the site in front of an application (`/api`, and whatever is not a file), with docker-compose.yml |
| [behind-proxy](behind-proxy) | behind nginx, Traefik or a load balancer: trusted proxies, the client's address; nginx.conf       |
| [tls-http3](tls-http3)       | HTTPS and HTTP/3 served by webfast itself, HTTP redirected                                        |
| [systemd](systemd)           | webfast as a hardened systemd service, without Docker                                             |

Try one with the image (`docker build -t webfast .` in the project's root) and a built site in
`./public`:

```bash
docker run --rm -p 8080:8080 -v "$PWD/public:/srv:ro" \
  -v "$PWD/recipes/static-site/Caddyfile:/etc/webfast/Caddyfile:ro" webfast
```

Check a configuration of your own before deploying it — it is parsed, compiled and its files are
loaded, and anything outside the supported subset is named with its line:

```bash
webfast validate --config Caddyfile
docker run --rm -v "$PWD/public:/srv:ro" -v "$PWD/Caddyfile:/etc/webfast/Caddyfile:ro" webfast \
  validate --config /etc/webfast/Caddyfile
```

All of them listen on plain HTTP on :8080 but `tls-http3`; put a TLS-terminating proxy in front
(`behind-proxy`), or serve TLS directly (`tls-http3`). [docs/configuration.md](../docs/configuration.md)
lists what a Caddyfile may contain, [docs/operations.md](../docs/operations.md) how to run it.
