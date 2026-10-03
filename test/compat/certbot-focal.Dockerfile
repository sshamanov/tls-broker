# Certbot as packaged by Ubuntu 20.04 (python3-certbot 0.40), for
# test/compat/run.sh.
FROM ubuntu:20.04
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends certbot ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["certbot"]
