ARG WOL_VERSION=0.1.0@sha256:5478fc28aa98e1a1f1fafcc907080680832e465a87735671924675f724446b77
ARG MC_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

# Stage 1: microcheck binaries
FROM ghcr.io/tarampampam/microcheck:${MC_VERSION} AS microcheck

# Stage 2: wol runtime image
FROM ghcr.io/trugamr/wol:${WOL_VERSION}

# Copy only the HTTP checker
COPY --from=microcheck /bin/httpcheck /usr/bin/httpcheck
