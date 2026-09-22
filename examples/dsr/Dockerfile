FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ipvsadm iproute2 procps python3 \
 && rm -rf /var/lib/apt/lists/*
COPY backend.py client.py /opt/dsr/
