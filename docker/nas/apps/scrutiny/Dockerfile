ARG SCRUTINY_VERSION=v0.9.5-collector@sha256:e55394663d4430af7dec36b1979785a2a2481b317047077eac84acb8305d583d
ARG MICROCHECK_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

FROM ghcr.io/tarampampam/microcheck:${MICROCHECK_VERSION} AS microcheck

FROM ghcr.io/analogj/scrutiny:${SCRUTINY_VERSION}

# Add a static HTTP probe for the configured Scrutiny API.
COPY --from=microcheck /bin/httpcheck /bin/httpcheck
