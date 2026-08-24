#!/usr/bin/env python3
"""Synchronize Traefik HTTP router hosts to AdGuard Home DNS rewrites."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import signal
import time
import urllib.error
import urllib.request
from pathlib import Path


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
LOG = logging.getLogger("adguard-dns-companion")
STOP = False
HOST_CALL = re.compile(r"(?<![A-Za-z])Host\(([^)]*)\)")
QUOTED_HOST = re.compile(r"""[`'"]([^`'"]+)[`'"]""")


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


ADGUARD_URL = required_env("ADGUARD_URL").rstrip("/")
ADGUARD_USERNAME = required_env("ADGUARD_USERNAME")
ADGUARD_PASSWORD = required_env("ADGUARD_PASSWORD")
DNS_DOMAIN = required_env("DNS_DOMAIN").lower().rstrip(".")
DNS_TARGET = required_env("DNS_TARGET").lower().rstrip(".")
TRAEFIK_API_URL = os.getenv("TRAEFIK_API_URL", "http://traefik:8080/api/http/routers")
STATE_FILE = Path(os.getenv("STATE_FILE", "/data/managed-hosts.json"))
POLL_INTERVAL = max(5, int(os.getenv("POLL_INTERVAL", "30")))
AUTH_TOKEN = base64.b64encode(f"{ADGUARD_USERNAME}:{ADGUARD_PASSWORD}".encode()).decode()


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
        raise RuntimeError(f"request to {url} failed ({error.code}): {detail}") from error
    return json.loads(payload) if payload else None


def traefik_hosts() -> set[str]:
    routers = request_json(TRAEFIK_API_URL)
    if not isinstance(routers, list):
        raise RuntimeError("Traefik returned an unexpected router response")
    hosts: set[str] = set()
    for router in routers:
        if not isinstance(router, dict) or router.get("status") == "disabled":
            continue
        rule = str(router.get("rule", ""))
        for call in HOST_CALL.findall(rule):
            for raw_host in QUOTED_HOST.findall(call):
                host = raw_host.lower().rstrip(".")
                if host == DNS_DOMAIN or host.endswith(f".{DNS_DOMAIN}"):
                    hosts.add(host)
    if not hosts:
        raise RuntimeError(f"Traefik returned no Host rules beneath {DNS_DOMAIN}; refusing to reconcile")
    return hosts


def rewrites() -> set[tuple[str, str]]:
    result = request_json(f"{ADGUARD_URL}/control/rewrite/list", authenticated=True)
    if not isinstance(result, list):
        raise RuntimeError("AdGuard returned an unexpected rewrite response")
    return {(str(item["domain"]), str(item["answer"])) for item in result}


def add_rewrite(domain: str, answer: str) -> None:
    request_json(
        f"{ADGUARD_URL}/control/rewrite/add",
        body={"domain": domain, "answer": answer},
        authenticated=True,
    )
    LOG.info("added rewrite https://%s -> %s", domain, answer)


def delete_rewrite(domain: str, answer: str) -> None:
    request_json(
        f"{ADGUARD_URL}/control/rewrite/delete",
        body={"domain": domain, "answer": answer},
        authenticated=True,
    )
    LOG.info("deleted rewrite https://%s -> %s", domain, answer)


def load_managed_hosts() -> set[str]:
    try:
        result = json.loads(STATE_FILE.read_text())
    except FileNotFoundError:
        return set()
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read {STATE_FILE}: {error}") from error
    if not isinstance(result, list):
        raise RuntimeError(f"{STATE_FILE} must contain a JSON array")
    return {str(host) for host in result}


def save_managed_hosts(hosts: set[str]) -> None:
    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(sorted(hosts), indent=2) + "\n")
    temporary.replace(STATE_FILE)


def reconcile() -> None:
    desired_hosts = traefik_hosts()
    managed_hosts = load_managed_hosts()
    existing = rewrites()
    desired = {(host, DNS_TARGET) for host in desired_hosts}

    # Add exact records first so removing the wildcard cannot interrupt Docker routes.
    for domain, answer in sorted(desired - existing):
        add_rewrite(domain, answer)
        existing.add((domain, answer))

    # A live Traefik router owns its exact hostname; remove conflicting answers.
    for domain, answer in sorted(existing):
        if domain in desired_hosts and (domain, answer) not in desired:
            delete_rewrite(domain, answer)

    wildcard = (f"*.{DNS_DOMAIN}", DNS_TARGET)
    if wildcard in existing:
        delete_rewrite(*wildcard)

    # Only prune records recorded as companion-owned during an earlier successful run.
    for stale_host in sorted(managed_hosts - desired_hosts):
        stale = (stale_host, DNS_TARGET)
        if stale in existing:
            delete_rewrite(*stale)

    save_managed_hosts(desired_hosts)
    LOG.info("reconciled %d Traefik hostname(s)", len(desired_hosts))


def stop(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def main() -> None:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not STOP:
        try:
            reconcile()
        except (OSError, RuntimeError, ValueError, urllib.error.URLError) as error:
            LOG.error("reconciliation failed: %s", error)
        for _ in range(POLL_INTERVAL):
            if STOP:
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
