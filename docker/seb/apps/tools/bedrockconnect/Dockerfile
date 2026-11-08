ARG BEDROCKCONNECT_VERSION=1.66@sha256:6fbbe37a4d94af7d60fb399d0b55cd70a00c5dfee76dbb859844a48cf74ebcf6
ARG MC_MONITOR_VERSION=1.19.0@sha256:43adc7c69fad95f52422482b53b03f4985155029b54a2de9df56c9fbe6287292

FROM docker.io/itzg/mc-monitor:${MC_MONITOR_VERSION} AS mc-monitor

FROM docker.io/pugmatt/bedrock-connect:${BEDROCKCONNECT_VERSION}

# Add the Bedrock-aware healthcheck binary without modifying the runtime dependencies.
COPY --from=mc-monitor /mc-monitor /usr/bin/mc-monitor
