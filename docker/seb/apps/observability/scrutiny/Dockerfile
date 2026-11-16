ARG SCRUTINY_VERSION=v0.10.0-collector@sha256:372493d3edf473571b806efb5922e8868537af644b3817536695cae05abd4f2c
ARG MICROCHECK_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

FROM ghcr.io/tarampampam/microcheck:${MICROCHECK_VERSION} AS microcheck

FROM ghcr.io/analogj/scrutiny:${SCRUTINY_VERSION}

# Add a static HTTP probe for the configured Scrutiny API.
COPY --from=microcheck /bin/httpcheck /bin/httpcheck
