#!/usr/bin/env python3

import base64
import json
import logging
import os
import re
import socket
import sys
import time
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

DOCKER_SOCKET = "/var/run/docker.sock"

ADGUARD_URL = os.environ["ADGUARD_URL"].rstrip("/")
ADGUARD_USERNAME = os.environ["ADGUARD_USERNAME"]
ADGUARD_PASSWORD = os.environ["ADGUARD_PASSWORD"]

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))
STATE_FILE = os.getenv("STATE_FILE", "/data/state.json")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(message)s",
)

log = logging.getLogger("adguard-dns-companion")


# -----------------------------------------------------------------------------
# Docker HTTP client
# -----------------------------------------------------------------------------

class UnixHTTPConnection(HTTPConnection):
    def __init__(self, socket_path):
        super().__init__("localhost")
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)


def docker_request(method, path):
    conn = UnixHTTPConnection(DOCKER_SOCKET)

    try:
        conn.request(method, path)
        response = conn.getresponse()

        body = response.read()

        if response.status >= 400:
            raise RuntimeError(
                f"Docker API returned HTTP {response.status}: "
                f"{body.decode(errors='replace')}"
            )

        if not body:
            return None

        return json.loads(body)

    finally:
        conn.close()


def get_running_containers():
    return docker_request(
        "GET",
        "/containers/json?all=false",
    )


# -----------------------------------------------------------------------------
# AdGuard HTTP client
# -----------------------------------------------------------------------------

def adguard_connection():
    parsed = urlparse(ADGUARD_URL)

    if parsed.scheme == "https":
        return HTTPSConnection(parsed.netloc, timeout=10)

    if parsed.scheme == "http":
        return HTTPConnection(parsed.netloc, timeout=10)

    raise RuntimeError(
        f"Unsupported ADGUARD_URL scheme: {parsed.scheme}"
    )


def adguard_request(method, path, payload=None):
    conn = adguard_connection()

    auth = base64.b64encode(
        f"{ADGUARD_USERNAME}:{ADGUARD_PASSWORD}".encode()
    ).decode()

    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    body = None

    if payload is not None:
        body = json.dumps(payload).encode()

    try:
        conn.request(
            method,
            path,
            body=body,
            headers=headers,
        )

        response = conn.getresponse()
        response_body = response.read()

        if response.status >= 400:
            raise RuntimeError(
                f"AdGuard API returned HTTP {response.status}: "
                f"{response_body.decode(errors='replace')}"
            )

        if not response_body:
            return None

        return json.loads(response_body)

    finally:
        conn.close()


# -----------------------------------------------------------------------------
# AdGuard rewrites
# -----------------------------------------------------------------------------

def get_rewrites():
    result = adguard_request(
        "GET",
        "/control/rewrite/list",
    )

    if not isinstance(result, list):
        raise RuntimeError(
            f"Unexpected AdGuard rewrite response: {result!r}"
        )

    return result


def rewrite_key(domain, answer):
    return f"{domain}\0{answer}"


def rewrite_exists(rewrites, domain, answer):
    return any(
        item.get("domain") == domain
        and item.get("answer") == answer
        for item in rewrites
    )


def add_rewrite(domain, answer):
    log.info(
        "Adding AdGuard rewrite: %s -> %s",
        domain,
        answer,
    )

    adguard_request(
        "POST",
        "/control/rewrite/add",
        {
            "domain": domain,
            "answer": answer,
        },
    )


def delete_rewrite(domain, answer):
    log.info(
        "Removing owned AdGuard rewrite: %s -> %s",
        domain,
        answer,
    )

    adguard_request(
        "POST",
        "/control/rewrite/delete",
        {
            "domain": domain,
            "answer": answer,
        },
    )


# -----------------------------------------------------------------------------
# State
# -----------------------------------------------------------------------------

def load_state():
    if not os.path.exists(STATE_FILE):
        return {
            "version": 1,
            "records": {},
        }

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)

        if state.get("version") != 1:
            log.warning(
                "Ignoring incompatible state file: %s",
                STATE_FILE,
            )

            return {
                "version": 1,
                "records": {},
            }

        if not isinstance(state.get("records"), dict):
            raise ValueError("records must be an object")

        return state

    except Exception as exc:
        log.warning(
            "Unable to load state file %s: %s",
            STATE_FILE,
            exc,
        )

        return {
            "version": 1,
            "records": {},
        }


def save_state(state):
    directory = os.path.dirname(STATE_FILE)

    if directory:
        os.makedirs(directory, exist_ok=True)

    temporary = f"{STATE_FILE}.tmp"

    with open(temporary, "w", encoding="utf-8") as f:
        json.dump(
            state,
            f,
            indent=2,
            sort_keys=True,
        )
        f.write("\n")

    os.replace(temporary, STATE_FILE)


# -----------------------------------------------------------------------------
# Traefik label parsing
# -----------------------------------------------------------------------------

ROUTER_RULE_RE = re.compile(
    r"^traefik\.http\.routers\.([^\.]+)\.rule$"
)

HOST_FUNCTION_RE = re.compile(
    r"Host\((.*?)\)",
    re.IGNORECASE,
)

HOST_VALUE_RE = re.compile(
    r"[`\"]([^`\"]+)[`\"]"
)


def extract_hosts(rule):
    """
    Extract all exact Host() values from a Traefik rule.

    Examples:

      Host(`foo.example.com`)
      Host(`foo.example.com`, `bar.example.com`)
      Host(`foo.example.com`) || Host(`bar.example.com`)
    """

    hosts = set()

    for match in HOST_FUNCTION_RE.finditer(rule):
        arguments = match.group(1)

        for value in HOST_VALUE_RE.findall(arguments):
            value = value.strip().lower()

            if value:
                hosts.add(value)

    return sorted(hosts)


def get_desired_records(containers):
    """
    Return:

      {
        "hostname\\0target": {
          "hostname": "...",
          "answer": "...",
          "owners": [
            {
              "container_id": "...",
              "container_name": "...",
              "router": "..."
            }
          ]
        }
      }

    Multiple containers/routers can own the same exact DNS record.
    """

    desired = {}

    for container in containers:
        container_id = container["Id"]

        names = container.get("Names") or []
        container_name = names[0].lstrip("/") if names else container_id[:12]

        labels = container.get("Labels") or {}

        target = labels.get("adguard.dns")

        # adguard.dns is explicitly opt-in.
        if not target:
            continue

        target = target.strip()

        if not target:
            continue

        for label, rule in labels.items():
            match = ROUTER_RULE_RE.match(label)

            if not match:
                continue

            router_name = match.group(1)

            if not rule:
                continue

            hosts = extract_hosts(rule)

            if not hosts:
                log.debug(
                    "Ignoring router %s/%s: no exact Host() rule found",
                    container_name,
                    router_name,
                )
                continue

            for hostname in hosts:
                key = rewrite_key(hostname, target)

                record = desired.setdefault(
                    key,
                    {
                        "hostname": hostname,
                        "answer": target,
                        "owners": [],
                    },
                )

                owner = {
                    "container_id": container_id,
                    "container_name": container_name,
                    "router": router_name,
                }

                if owner not in record["owners"]:
                    record["owners"].append(owner)

    return desired


# -----------------------------------------------------------------------------
# Reconciliation
# -----------------------------------------------------------------------------

def reconcile():
    containers = get_running_containers()
    rewrites = get_rewrites()
    state = load_state()

    previous_records = state["records"]
    desired_records = get_desired_records(containers)

    current_rewrites = {
        rewrite_key(
            item.get("domain", ""),
            item.get("answer", ""),
        )
        for item in rewrites
        if item.get("domain") and item.get("answer")
    }

    previous_keys = set(previous_records)
    desired_keys = set(desired_records)

    # -------------------------------------------------------------------------
    # Remove records that were previously owned by us but are no longer
    # required by any current Docker container/router.
    #
    # IMPORTANT:
    # We only delete records present in our state file.
    # Manual AdGuard entries are never considered here.
    # -------------------------------------------------------------------------

    stale_keys = previous_keys - desired_keys

    for key in sorted(stale_keys):
        record = previous_records[key]

        hostname = record["hostname"]
        answer = record["answer"]

        # If somebody already removed it, there is nothing to do.
        if key in current_rewrites:
            delete_rewrite(hostname, answer)

            current_rewrites.discard(key)

        else:
            log.debug(
                "Owned rewrite already absent: %s -> %s",
                hostname,
                answer,
            )

    # -------------------------------------------------------------------------
    # Build the new ownership state.
    # -------------------------------------------------------------------------

    new_records = {}

    for key, desired in sorted(desired_records.items()):
        hostname = desired["hostname"]
        answer = desired["answer"]

        previously_owned = key in previous_records
        exists = key in current_rewrites

        if exists:
            if previously_owned:
                # Still ours. Refresh owner metadata.
                new_records[key] = desired

                log.debug(
                    "Keeping owned rewrite: %s -> %s",
                    hostname,
                    answer,
                )

            else:
                # IMPORTANT:
                #
                # The record already existed before we owned it.
                # Therefore it may be a manual record.
                #
                # Do NOT claim ownership.
                log.info(
                    "Leaving existing unowned rewrite untouched: "
                    "%s -> %s",
                    hostname,
                    answer,
                )

        else:
            # Record does not exist, so we create it and therefore own it.
            add_rewrite(hostname, answer)

            current_rewrites.add(key)
            new_records[key] = desired

    state["records"] = new_records

    save_state(state)

    log.info(
        "Reconciliation complete: %d desired, %d owned",
        len(desired_records),
        len(new_records),
    )


# -----------------------------------------------------------------------------
# Healthcheck
# -----------------------------------------------------------------------------

def healthcheck():
    try:
        get_running_containers()
        get_rewrites()

        log.info("Healthcheck OK")
        return 0

    except Exception as exc:
        log.error("Healthcheck failed: %s", exc)
        return 1


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    if "--healthcheck" in sys.argv:
        return healthcheck()

    log.info(
        "Starting AdGuard DNS companion "
        "(poll interval: %ss)",
        POLL_INTERVAL,
    )

    while True:
        try:
            reconcile()

        except KeyboardInterrupt:
            log.info("Stopping")
            return 0

        except Exception:
            log.exception("Reconciliation failed")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
