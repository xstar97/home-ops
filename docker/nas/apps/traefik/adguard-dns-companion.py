#!/usr/bin/env python3
"""Synchronize Traefik HTTP router hosts to AdGuard Home DNS rewrites."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)

LOG = logging.getLogger("adguard-dns-companion")

STOP = False

DOCKER_SOCKET = os.getenv(
    "DOCKER_SOCKET",
    "/var/run/docker.sock",
)

DOCKER_API_URL = "http://localhost"

TRAEFIK_API_URL = os.getenv(
    "TRAEFIK_API_URL",
    "http://traefik:8080/api/http/routers",
)

STATE_FILE = Path(
    os.getenv(
        "STATE_FILE",
        "/data/managed-hosts.json",
    )
)

POLL_INTERVAL = max(
    5,
    int(os.getenv("POLL_INTERVAL", "30")),
)

HOST_CALL = re.compile(
    r"(?<![A-Za-z])Host\(([^)]*)\)"
)

QUOTED_HOST = re.compile(
    r"""[`'"]([^`'"]+)[`'"]"""
)

LABEL_ENABLED = "adguard.dns-companion.enabled"
LABEL_DOMAIN = "adguard.dns-companion.domain"
LABEL_TARGET = "adguard.dns-companion.target"


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()

    if not value:
        raise RuntimeError(f"{name} is required")

    return value


ADGUARD_URL = required_env("ADGUARD_URL").rstrip("/")
ADGUARD_USERNAME = required_env("ADGUARD_USERNAME")
ADGUARD_PASSWORD = required_env("ADGUARD_PASSWORD")

AUTH_TOKEN = base64.b64encode(
    f"{ADGUARD_USERNAME}:{ADGUARD_PASSWORD}".encode()
).decode()


def request_json(
    url: str,
    *,
    body: dict[str, str] | None = None,
    authenticated: bool = False,
    unix_socket: bool = False,
) -> object:
    """
    Make a JSON HTTP request.

    The unix_socket argument is reserved for the Docker API.
    The standard urllib client cannot directly use a Unix socket,
    so Docker API requests are handled separately below.
    """

    if unix_socket:
        raise RuntimeError(
            "Unix socket requests must use docker_request()"
        )

    headers = {
        "Accept": "application/json",
    }

    if authenticated:
        headers["Authorization"] = (
            f"Basic {AUTH_TOKEN}"
        )

    data = None

    if body is not None:
        headers["Content-Type"] = (
            "application/json"
        )
        data = json.dumps(body).encode()

    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=10,
        ) as response:
            payload = response.read()

    except urllib.error.HTTPError as error:
        detail = error.read().decode(
            errors="replace"
        )

        raise RuntimeError(
            f"request to {url} failed "
            f"({error.code}): {detail}"
        ) from error

    except urllib.error.URLError as error:
        raise RuntimeError(
            f"request to {url} failed: {error}"
        ) from error

    return (
        json.loads(payload)
        if payload
        else None
    )


def docker_request(
    path: str,
) -> object:
    """
    Query the Docker Engine API through the mounted
    Unix socket.

    This intentionally uses only the Docker API endpoints
    required to discover the Traefik container and its labels.
    """

    try:
        import socket
    except ImportError as error:
        raise RuntimeError(
            "Python socket module unavailable"
        ) from error

    request = (
        f"GET {path} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    sock = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    try:
        sock.settimeout(10)
        sock.connect(DOCKER_SOCKET)
        sock.sendall(request)

        chunks: list[bytes] = []

        while True:
            chunk = sock.recv(65536)

            if not chunk:
                break

            chunks.append(chunk)

    except OSError as error:
        raise RuntimeError(
            f"Docker API request failed: {error}"
        ) from error

    finally:
        sock.close()

    response = b"".join(chunks)

    try:
        header, payload = response.split(
            b"\r\n\r\n",
            1,
        )
    except ValueError as error:
        raise RuntimeError(
            "Docker API returned an invalid response"
        ) from error

    status_line = header.split(
        b"\r\n",
        1,
    )[0]

    match = re.search(
        rb"HTTP/\d\.\d\s+(\d+)",
        status_line,
    )

    if not match:
        raise RuntimeError(
            "Docker API returned an invalid status"
        )

    status = int(match.group(1))

    if status < 200 or status >= 300:
        raise RuntimeError(
            f"Docker API request {path} "
            f"failed with HTTP {status}"
        )

    # Docker may use chunked transfer encoding.
    if b"transfer-encoding: chunked" in (
        header.lower()
    ):
        payload = decode_chunked(payload)

    try:
        return json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Docker API returned invalid JSON "
            f"for {path}"
        ) from error


def decode_chunked(payload: bytes) -> bytes:
    """Decode a HTTP chunked response."""

    output = bytearray()
    position = 0

    while position < len(payload):
        end = payload.find(
            b"\r\n",
            position,
        )

        if end == -1:
            raise RuntimeError(
                "invalid chunked Docker response"
            )

        try:
            size = int(
                payload[position:end],
                16,
            )
        except ValueError as error:
            raise RuntimeError(
                "invalid Docker chunk size"
            ) from error

        position = end + 2

        if size == 0:
            break

        chunk_end = position + size

        if chunk_end > len(payload):
            raise RuntimeError(
                "truncated Docker chunk"
            )

        output.extend(
            payload[position:chunk_end]
        )

        position = chunk_end + 2

    return bytes(output)


def docker_labels() -> dict[str, str]:
    """
    Find the Traefik container and return its labels.

    The container is identified by:
        adguard.dns-companion.enabled=true
    """

    containers = docker_request(
        "/containers/json?all=1"
    )

    if not isinstance(containers, list):
        raise RuntimeError(
            "Docker returned an unexpected container response"
        )

    matches: list[dict[str, object]] = []

    for container in containers:
        if not isinstance(container, dict):
            continue

        labels = container.get("Labels")

        if not isinstance(labels, dict):
            continue

        enabled = str(
            labels.get(
                LABEL_ENABLED,
                "",
            )
        ).lower()

        if enabled in {
            "true",
            "1",
            "yes",
            "on",
        }:
            matches.append(container)

    if not matches:
        raise RuntimeError(
            "no container found with "
            f"{LABEL_ENABLED}=true"
        )

    if len(matches) > 1:
        names = []

        for container in matches:
            name = container.get("Names")

            if isinstance(name, list):
                names.extend(
                    str(item)
                    for item in name
                )

        raise RuntimeError(
            "multiple containers have "
            f"{LABEL_ENABLED}=true: "
            + ", ".join(names)
        )

    labels = matches[0].get("Labels")

    if not isinstance(labels, dict):
        raise RuntimeError(
            "Traefik container has no Docker labels"
        )

    return {
        str(key): str(value)
        for key, value in labels.items()
    }


def companion_config() -> tuple[str, str]:
    """
    Read the companion configuration from Traefik labels.

    Environment variables remain supported as fallbacks.
    Labels take precedence.
    """

    labels = docker_labels()

    domain = labels.get(
        LABEL_DOMAIN,
        os.getenv("DNS_DOMAIN", ""),
    ).strip().lower().rstrip(".")

    target = labels.get(
        LABEL_TARGET,
        os.getenv("DNS_TARGET", ""),
    ).strip().lower().rstrip(".")

    if not domain:
        raise RuntimeError(
            f"{LABEL_DOMAIN} is required "
            "on the Traefik container"
        )

    if not target:
        raise RuntimeError(
            f"{LABEL_TARGET} is required "
            "on the Traefik container"
        )

    return domain, target


def traefik_hosts(
    domain: str,
) -> set[str]:
    routers = request_json(
        TRAEFIK_API_URL
    )

    if not isinstance(routers, list):
        raise RuntimeError(
            "Traefik returned an unexpected "
            "router response"
        )

    hosts: set[str] = set()

    for router in routers:
        if not isinstance(router, dict):
            continue

        if router.get("status") == "disabled":
            continue

        rule = str(
            router.get("rule", "")
        )

        for call in HOST_CALL.findall(rule):
            for raw_host in QUOTED_HOST.findall(
                call
            ):
                host = (
                    raw_host
                    .lower()
                    .rstrip(".")
                )

                if host == domain or host.endswith(
                    f".{domain}"
                ):
                    hosts.add(host)

    if not hosts:
        raise RuntimeError(
            "Traefik returned no Host rules "
            f"beneath {domain}; "
            "refusing to reconcile"
        )

    return hosts


def rewrites() -> set[tuple[str, str]]:
    result = request_json(
        f"{ADGUARD_URL}/control/rewrite/list",
        authenticated=True,
    )

    if not isinstance(result, list):
        raise RuntimeError(
            "AdGuard returned an unexpected "
            "rewrite response"
        )

    records: set[tuple[str, str]] = set()

    for item in result:
        if not isinstance(item, dict):
            continue

        if "domain" not in item or "answer" not in item:
            continue

        records.add(
            (
                str(item["domain"]).lower().rstrip("."),
                str(item["answer"]).lower().rstrip("."),
            )
        )

    return records


def add_rewrite(
    domain: str,
    answer: str,
) -> None:
    request_json(
        f"{ADGUARD_URL}/control/rewrite/add",
        body={
            "domain": domain,
            "answer": answer,
        },
        authenticated=True,
    )

    LOG.info(
        "added rewrite %s -> %s",
        domain,
        answer,
    )


def delete_rewrite(
    domain: str,
    answer: str,
) -> None:
    request_json(
        f"{ADGUARD_URL}/control/rewrite/delete",
        body={
            "domain": domain,
            "answer": answer,
        },
        authenticated=True,
    )

    LOG.info(
        "deleted rewrite %s -> %s",
        domain,
        answer,
    )


def load_managed_hosts() -> set[str]:
    try:
        result = json.loads(
            STATE_FILE.read_text()
        )

    except FileNotFoundError:
        return set()

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise RuntimeError(
            f"cannot read {STATE_FILE}: {error}"
        ) from error

    if not isinstance(result, list):
        raise RuntimeError(
            f"{STATE_FILE} must contain "
            "a JSON array"
        )

    return {
        str(host).lower().rstrip(".")
        for host in result
    }


def save_managed_hosts(
    hosts: set[str],
) -> None:
    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = STATE_FILE.with_suffix(
        ".tmp"
    )

    temporary.write_text(
        json.dumps(
            sorted(hosts),
            indent=2,
        )
        + "\n"
    )

    temporary.replace(STATE_FILE)


def reconcile() -> None:
    domain, target = companion_config()

    desired_hosts = traefik_hosts(domain)

    managed_hosts = load_managed_hosts()

    existing = rewrites()

    desired = {
        (
            host,
            target,
        )
        for host in desired_hosts
    }

    # Add exact records first.
    #
    # This prevents a DNS outage when an old wildcard
    # is about to be removed.
    for record in sorted(
        desired - existing
    ):
        add_rewrite(*record)
        existing.add(record)

    # A live Traefik router owns its exact hostname.
    # Remove conflicting answers for those hosts.
    for existing_domain, existing_answer in sorted(
        existing
    ):
        if (
            existing_domain in desired_hosts
            and (
                existing_domain,
                existing_answer,
            )
            not in desired
        ):
            delete_rewrite(
                existing_domain,
                existing_answer,
            )

    # Remove the wildcard for this DNS domain.
    #
    # Exact Traefik records are authoritative instead.
    wildcard = (
        f"*.{domain}",
        target,
    )

    if wildcard in existing:
        delete_rewrite(*wildcard)

    # Only remove stale records that this companion
    # successfully managed during an earlier run.
    for stale_host in sorted(
        managed_hosts - desired_hosts
    ):
        stale = (
            stale_host,
            target,
        )

        if stale in existing:
            delete_rewrite(*stale)

    save_managed_hosts(desired_hosts)

    LOG.info(
        "reconciled %d Traefik hostname(s) "
        "for %s -> %s",
        len(desired_hosts),
        domain,
        target,
    )


def healthcheck() -> None:
    # Verify Docker configuration first.
    domain, target = companion_config()

    if not domain:
        raise RuntimeError(
            "DNS domain is empty"
        )

    if not target:
        raise RuntimeError(
            "DNS target is empty"
        )

    # Verify Traefik API.
    routers = request_json(
        TRAEFIK_API_URL
    )

    if not isinstance(routers, list):
        raise RuntimeError(
            "Traefik API is unavailable"
        )

    # Verify AdGuard.
    status = request_json(
        f"{ADGUARD_URL}/control/status",
        authenticated=True,
    )

    if (
        not isinstance(status, dict)
        or status.get("protection_enabled")
        is not True
    ):
        raise RuntimeError(
            "AdGuard Home protection is not active"
        )


def stop(
    _signum: int,
    _frame: object,
) -> None:
    global STOP
    STOP = True


def main() -> None:
    signal.signal(
        signal.SIGTERM,
        stop,
    )

    signal.signal(
        signal.SIGINT,
        stop,
    )

    while not STOP:
        try:
            reconcile()

        except (
            OSError,
            RuntimeError,
            ValueError,
            urllib.error.URLError,
        ) as error:
            LOG.error(
                "reconciliation failed: %s",
                error,
            )

        for _ in range(POLL_INTERVAL):
            if STOP:
                break

            time.sleep(1)


if __name__ == "__main__":
    if "--healthcheck" in sys.argv[1:]:
        healthcheck()
    else:
        main()
