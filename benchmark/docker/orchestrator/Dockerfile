FROM python:3.10-slim

# Install Docker CLI, git, tar, gzip, curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    tar \
    gzip \
    ca-certificates \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-24.0.7.tgz | tar -xzC /tmp \
    && mv /tmp/docker/docker /usr/local/bin/ \
    && rm -rf /tmp/docker /var/lib/apt/lists/*

RUN pip install --no-cache-dir pyyaml scipy numpy

WORKDIR /benchmark
COPY docker/orchestrator/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

