ARG BEDROCKCONNECT_VERSION=1.66@sha256:6fbbe37a4d94af7d60fb399d0b55cd70a00c5dfee76dbb859844a48cf74ebcf6
ARG MC_MONITOR_VERSION=0.18.1@sha256:6e38245c074f5d15e28131657f48b41eaaac08d18a24131c545cc607345f92bb

FROM docker.io/itzg/mc-monitor:${MC_MONITOR_VERSION} AS mc-monitor

FROM docker.io/pugmatt/bedrock-connect:${BEDROCKCONNECT_VERSION}

# Add the Bedrock-aware healthcheck binary without modifying the runtime dependencies.
COPY --from=mc-monitor /mc-monitor /usr/bin/mc-monitor
