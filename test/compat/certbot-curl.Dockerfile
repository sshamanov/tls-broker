# certbot/certbot with curl, for the DNS-proxy suite of test/compat/run.sh:
# its manual hooks are curl one-liners, and the official image has no curl
# (a host running certbot normally does).
ARG CERTBOT_IMAGE=certbot/certbot:latest
FROM ${CERTBOT_IMAGE}
RUN apk add --no-cache curl
