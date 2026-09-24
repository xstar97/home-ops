ARG GATUS_VERSION=v5.37.0@sha256:094eb186e55235db367e90e9d56140e5897b7044c41de23cde4cc18e6da1242e
ARG MC_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

# Stage 1: microcheck binaries
FROM ghcr.io/tarampampam/microcheck:${MC_VERSION} AS microcheck

# Stage 2: distroless gatus runtime
FROM ghcr.io/twin/gatus:${GATUS_VERSION}

# Copy only the HTTP checker
COPY --from=microcheck /bin/httpcheck /usr/bin/httpcheck
