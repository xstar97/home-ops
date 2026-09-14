ARG SCRUTINY_VERSION=v0.9.4-collector@sha256:3f84c69d040877a521fdb92ff4bc31818bef8fb3dd52d0b796e0b76a342d7f41
ARG MICROCHECK_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

FROM ghcr.io/tarampampam/microcheck:${MICROCHECK_VERSION} AS microcheck

FROM ghcr.io/analogj/scrutiny:${SCRUTINY_VERSION}

# Add a static HTTP probe for the configured Scrutiny API.
COPY --from=microcheck /bin/httpcheck /bin/httpcheck
