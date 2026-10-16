# Security policy

webfast faces the internet, so we treat reports about it as a priority.

## Reporting a vulnerability

Please report it privately — not in a public issue, merge request or discussion:

- where the project is hosted on GitHub: the repository's **Security** tab → **Report a
  vulnerability** (private vulnerability reporting);
- where it is hosted on GitLab: a **new issue marked confidential**.

Tell us what you can of:

- the version (`webfast --version`) or the commit;
- the configuration that matters — a minimal Caddyfile, and the environment variables you set;
- what an attacker sends and what happens, ideally as commands we can run (`curl`, a short script);
- the impact as you see it, and whether the problem is already known or public.

We aim to acknowledge a report within 3 working days and to tell you within 7 whether we can
reproduce it and how serious we think it is. A fix for a serious problem should be released within
30 days, sooner when it is being exploited. We keep you informed on the way, agree the disclosure
date with you — when the fix is released, and at the latest 90 days after your report unless we
agree otherwise — and credit you in the release notes, unless you prefer not to be named.

## Supported versions

Until webfast reaches 1.0, security fixes go into the latest release only. Run the latest
version, or the latest image.

## What we treat as a vulnerability

Anything a client — or an upstream answer — can make webfast do that it should not, for example:

- serving a file outside a site's root, a hidden file (`file_server { hide }`) or a path a
  configuration answers with 404 by matcher;
- crashing the process, or making it hold memory, connections or CPU far out of proportion to what
  the client sends, despite the limits (docs/operations.md, Limits);
- request smuggling or response splitting between webfast and a proxy or an upstream;
- forging the client's address past `trusted_proxies`, or passing identity headers from an
  untrusted peer to an upstream;
- redirecting a browser off the site through a path, or reflecting request data into headers;
- flaws in how webfast sets up TLS, HTTP/2 or HTTP/3, including 0-RTT replay of unsafe methods.

Not vulnerabilities in webfast itself, though we still want to hear about them:

- problems in a dependency that webfast does not reach — please report those to the dependency;
  we follow the RustSec advisories with cargo-deny in CI (`deny.toml`);
- denial of service by sheer volume (rate limiting belongs in front of the server, or in a
  firewall), or by settings that remove a limit (`WEB_MAX_CONNECTIONS=0` and the like);
- a configuration doing what it says — a root that contains secrets serves them;
- the sample configuration (`sample/`) and the recipes (`recipes/`) as examples, unless the flaw
  would carry over into real use.

## How webfast keeps itself safe

- Rust: memory safety by construction. The few `unsafe` blocks are calls into the operating system
  — inotify and `statfs` (src/watch.rs), one socket option (src/sockets.rs) — and returning freed
  memory to the system (src/lib.rs).
- Limits against slow and greedy clients, in effect by default: connections per address and
  overall, header, idle and stall timeouts, a timeout for hung upstreams, bounded ranges, HTTP/3
  frame limits, a QUIC handshake budget (docs/operations.md, Limits).
- No configuration is half-understood: anything outside the supported Caddyfile subset stops the
  startup with its file and line.
- Files are served from memory: a request never opens a path on disk.
- Dependencies are checked on every CI pipeline — known vulnerabilities, licenses, sources
  (cargo-deny). The Docker image runs as an unprivileged user and needs no capabilities; the
  systemd recipe (recipes/systemd) sandboxes the service.
