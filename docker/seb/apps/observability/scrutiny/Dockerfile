ARG SCRUTINY_VERSION=v0.9.3-collector@sha256:9e3413b1992eee55cd4138a2e5b9083ce47f6f3ffce7d1c1eb17995c05728b3e
ARG MICROCHECK_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

FROM ghcr.io/tarampampam/microcheck:${MICROCHECK_VERSION} AS microcheck

FROM ghcr.io/analogj/scrutiny:${SCRUTINY_VERSION}

# Add a static HTTP probe for the configured Scrutiny API.
COPY --from=microcheck /bin/httpcheck /bin/httpcheck
