ARG WOL_VERSION=0.2.0@sha256:61583391a70557ef01fc3cc17b8f834e1e5ac4f4a51ab59fe3bbe33ed4fea0f5
ARG MC_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

# Stage 1: microcheck binaries
FROM ghcr.io/tarampampam/microcheck:${MC_VERSION} AS microcheck

# Stage 2: wol runtime image
FROM ghcr.io/trugamr/wol:${WOL_VERSION}

# Copy only the HTTP checker
COPY --from=microcheck /bin/httpcheck /usr/bin/httpcheck
