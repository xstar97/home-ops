ARG BEDROCKCONNECT_VERSION=1.66@sha256:6fbbe37a4d94af7d60fb399d0b55cd70a00c5dfee76dbb859844a48cf74ebcf6
ARG MC_MONITOR_VERSION=0.18.0@sha256:67d28629ccaa73d58bb441b0f73ca293fa53b81cbaf51041dddd65e0f0da22b6

FROM docker.io/itzg/mc-monitor:${MC_MONITOR_VERSION} AS mc-monitor

FROM docker.io/pugmatt/bedrock-connect:${BEDROCKCONNECT_VERSION}

# Add the Bedrock-aware healthcheck binary without modifying the runtime dependencies.
COPY --from=mc-monitor /mc-monitor /usr/bin/mc-monitor
