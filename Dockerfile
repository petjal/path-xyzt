FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="path-xyzt-probe"
LABEL org.opencontainers.image.description="Outside-in network telemetry probe container"
LABEL org.opencontainers.image.version="1.6.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        mtr-tiny \
        tcptraceroute \
        dnsutils \
        ca-certificates \
        jq \
        curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -u 10001 -m -s /bin/bash xyztuser

WORKDIR /app

COPY scripts/strawman_collector.py /app/collector.py
COPY targets.txt /app/targets.txt
COPY docker_entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/collector.py /app/entrypoint.sh && \
    chown -R xyztuser:xyztuser /app

USER xyztuser

ENTRYPOINT ["/app/entrypoint.sh"]
