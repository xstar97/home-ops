ARG WOL_VERSION=0.3.0@sha256:ba2df1879f0fa945b767bdf6790c01a18bc7966b2a21b473ce0c284f030fbccb
ARG MC_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

# Stage 1: microcheck binaries
FROM ghcr.io/tarampampam/microcheck:${MC_VERSION} AS microcheck

# Stage 2: wol runtime image
FROM ghcr.io/trugamr/wol:${WOL_VERSION}

# Copy only the HTTP checker
COPY --from=microcheck /bin/httpcheck /usr/bin/httpcheck
