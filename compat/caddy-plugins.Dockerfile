# Caddy with the plugins whose Caddyfile syntax webfast also reads, for the compat scenarios that
# use them (compat/run.sh builds it when a scenario needs it): caddy-ratelimit (`rate_limit`) and
# cache-handler (`cache`).
#
#   docker build -t webfast-compat-caddy-plugins -f compat/caddy-plugins.Dockerfile compat
FROM caddy:2-builder AS build
RUN xcaddy build --with github.com/mholt/caddy-ratelimit --with github.com/caddyserver/cache-handler

FROM caddy:2-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy
