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

HOST_CALL = re.compile(r"(?<![A-Za-z])Host\(([^)]*)\)")
QUOTED_HOST = re.compile(r"""[`'"]([^`'"]+)[`'"]""")


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


# Secrets / runtime settings only.
ADGUARD_URL = required_env("ADGUARD_URL").rstrip("/")
ADGUARD_USERNAME = required_env("ADGUARD_USERNAME")
ADGUARD_PASSWORD = required_env("ADGUARD_PASSWORD")

TRAEFIK_API_URL = os.getenv(
    "TRAEFIK_API_URL",
    "http://traefik:8080/api/http/routers",
)

DNS_TARGET = required_env("DNS_TARGET").rstrip(".")

STATE_FILE = Path(os.getenv("STATE_FILE", "/data/managed-hosts.json"))
POLL_INTERVAL = max(5, int(os.getenv("POLL_INTERVAL", "30")))

AUTH_TOKEN = base64.b64encode(
    f"{ADGUARD_USERNAME}:{ADGUARD_PASSWORD}".encode()
).decode()


def request_json(
    url: str,
    *,
    body: dict[str, str] | None = None,
    authenticated: bool = False,
) -> object:
    headers = {"Accept": "application/json"}

    if authenticated:
        headers["Authorization"] = f"Basic {AUTH_TOKEN}"

    data = None

    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()

    request = urllib.request.Request(url, data=data, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(
            f"request to {url} failed ({error.code}): {detail}"
        ) from error

    return json.loads(payload) if payload else None


def traefik_hosts() -> set[str]:
    routers = request_json(TRAEFIK_API_URL)

    if not isinstance(routers, list):
        raise RuntimeError("Traefik returned an unexpected router response")

    hosts: set[str] = set()

    for router in routers:
        if not isinstance(router, dict):
            continue

        if router.get("status") == "disabled":
            continue

        rule = str(router.get("rule", ""))

        for call in HOST_CALL.findall(rule):
            for raw_host in QUOTED_HOST.findall(call):
                host = raw_host.lower().rstrip(".")

                # Ignore IP addresses.
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                    continue

                hosts.add(host)

    if not hosts:
        raise RuntimeError(
            "Traefik returned no usable Host rules; "
            "refusing to reconcile"
        )

    return hosts


def dns_domain(hosts: set[str]) -> str:
    """
    Infer the common DNS suffix from Traefik hosts.

    Example:
        grafana.nas.local
        plex.nas.local
        traefik.nas.local

    -> nas.local
    """

    if not hosts:
        raise RuntimeError("cannot determine DNS domain from empty host set")

    parts = [host.split(".") for host in hosts]

    if any(len(part) < 2 for part in parts):
        raise RuntimeError(
            "cannot infer DNS domain; all Traefik hosts must be FQDNs"
        )

    suffix = list(parts[0][-2:])

    for part in parts[1:]:
        while suffix and part[-len(suffix):] != suffix:
            suffix.pop()

    if len(suffix) < 2:
        raise RuntimeError(
            "Traefik hosts do not share a common DNS suffix"
        )

    return ".".join(suffix)


def rewrites() -> set[tuple[str, str]]:
    result = request_json(
        f"{ADGUARD_URL}/control/rewrite/list",
        authenticated=True,
    )

    if not isinstance(result, list):
        raise RuntimeError(
            "AdGuard returned an unexpected rewrite response"
        )

    return {
        (str(item["domain"]), str(item["answer"]))
        for item in result
    }


def add_rewrite(domain: str, answer: str) -> None:
    request_json(
        f"{ADGUARD_URL}/control/rewrite/add",
        body={
            "domain": domain,
            "answer": answer,
        },
        authenticated=True,
    )

    LOG.info("added %s -> %s", domain, answer)


def delete_rewrite(domain: str, answer: str) -> None:
    request_json(
        f"{ADGUARD_URL}/control/rewrite/delete",
        body={
            "domain": domain,
            "answer": answer,
        },
        authenticated=True,
    )

    LOG.info("deleted %s -> %s", domain, answer)


def load_managed_hosts() -> set[str]:
    try:
        result = json.loads(STATE_FILE.read_text())
    except FileNotFoundError:
        return set()
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"cannot read {STATE_FILE}: {error}"
        ) from error

    if not isinstance(result, list):
        raise RuntimeError(
            f"{STATE_FILE} must contain a JSON array"
        )

    return {str(host) for host in result}


def save_managed_hosts(hosts: set[str]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(sorted(hosts), indent=2) + "\n"
    )
    temporary.replace(STATE_FILE)


def reconcile() -> None:
    desired_hosts = traefik_hosts()
    domain = dns_domain(desired_hosts)

    managed_hosts = load_managed_hosts()
    existing = rewrites()

    desired = {
        (host, DNS_TARGET)
        for host in desired_hosts
    }

    # Add exact records first.
    for record in sorted(desired - existing):
        add_rewrite(*record)
        existing.add(record)

    # Remove conflicting answers from live Traefik hosts.
    for existing_domain, existing_answer in sorted(existing):
        if (
            existing_domain in desired_hosts
            and (existing_domain, existing_answer) not in desired
        ):
            delete_rewrite(
                existing_domain,
                existing_answer,
            )

    # Remove the old wildcard if present.
    wildcard = (
        f"*.{domain}",
        DNS_TARGET,
    )

    if wildcard in existing:
        delete_rewrite(*wildcard)

    # Remove stale records previously managed by us.
    for stale_host in sorted(managed_hosts - desired_hosts):
        stale = (
            stale_host,
            DNS_TARGET,
        )

        if stale in existing:
            delete_rewrite(*stale)

    save_managed_hosts(desired_hosts)

    LOG.info(
        "reconciled %d Traefik hostname(s) for %s",
        len(desired_hosts),
        domain,
    )


def healthcheck() -> None:
    status = request_json(
        f"{ADGUARD_URL}/control/status",
        authenticated=True,
    )

    if (
        not isinstance(status, dict)
        or status.get("protection_enabled") is not True
    ):
        raise RuntimeError(
            "AdGuard Home protection is not active"
        )


def stop(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def main() -> None:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    while not STOP:
        try:
            reconcile()
        except (
            OSError,
            RuntimeError,
            ValueError,
            urllib.error.URLError,
        ) as error:
            LOG.error("reconciliation failed: %s", error)

        for _ in range(POLL_INTERVAL):
            if STOP:
                break

            time.sleep(1)


if __name__ == "__main__":
    if "--healthcheck" in sys.argv[1:]:
        healthcheck()
    else:
        main()
