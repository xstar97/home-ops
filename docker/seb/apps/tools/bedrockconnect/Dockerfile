ARG BEDROCKCONNECT_VERSION=1.66@sha256:6fbbe37a4d94af7d60fb399d0b55cd70a00c5dfee76dbb859844a48cf74ebcf6
ARG MC_MONITOR_VERSION=1.18.3@sha256:f30307791501a6eec4190f4b2c32296d5f17c6673aceb18943c5ed0f56f4edfe

FROM docker.io/itzg/mc-monitor:${MC_MONITOR_VERSION} AS mc-monitor

FROM docker.io/pugmatt/bedrock-connect:${BEDROCKCONNECT_VERSION}

# Add the Bedrock-aware healthcheck binary without modifying the runtime dependencies.
COPY --from=mc-monitor /mc-monitor /usr/bin/mc-monitor
