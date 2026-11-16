ARG PRUNEMATE_VERSION=1.4.0@sha256:5fd5dfc06e0e4ab4878a2f03b77b0dfdb0fb5f7ecc170caaf291f0f285a48e6c
ARG MC_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

# Stage 1: microcheck binaries
FROM ghcr.io/tarampampam/microcheck:${MC_VERSION} AS microcheck

# Stage 2: runtime image
FROM anoniemerd/prunemate:${PRUNEMATE_VERSION}

# Copy only the HTTP checker
COPY --from=microcheck /bin/httpcheck /usr/bin/httpcheck
