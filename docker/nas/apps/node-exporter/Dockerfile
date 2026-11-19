ARG NODE_EXPORTER_VERSION=v1.13.1-distroless@sha256:6a6f3d5827f79bf08ac881f2914cec36a1e3b77b9eeb4891bfb847bdfda86123
ARG MICROCHECK_VERSION=1.4.0@sha256:c9f79cd408626de7c10f2d487d67339f49adf0ba61dde96ede65343269db1f85

FROM ghcr.io/tarampampam/microcheck:${MICROCHECK_VERSION} AS microcheck

FROM quay.io/prometheus/node-exporter:${NODE_EXPORTER_VERSION}

# Add a static HTTP probe while retaining the distroless runtime.
COPY --from=microcheck /bin/httpcheck /bin/httpcheck
