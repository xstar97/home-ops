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

DYNAMIC_CONFIG_DIR = os.getenv(
    "DYNAMIC_CONFIG_DIR",
    "/etc/traefik/dynamic",
)

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
# Host extraction
# -----------------------------------------------------------------------------

HOST_FUNCTION_RE = re.compile(
    r"Host\((.*?)\)",
    re.IGNORECASE,
)

HOST_VALUE_RE = re.compile(
    r"[`\"]([^`\"]+)[`\"]"
)


def extract_hosts(rule):
    """
    Extract exact Host() values.

    Supports:

        Host(`foo.example.com`)

        Host(`foo.example.com`, `bar.example.com`)

        Host(`foo.example.com`) || Host(`bar.example.com`)

        Host(`foo.example.com`) && Path(`/metrics`)
    """

    hosts = set()

    for match in HOST_FUNCTION_RE.finditer(rule):
        arguments = match.group(1)

        for value in HOST_VALUE_RE.findall(arguments):
            value = value.strip().lower()

            if value:
                hosts.add(value)

    return sorted(hosts)


# -----------------------------------------------------------------------------
# Docker label discovery
# -----------------------------------------------------------------------------

ROUTER_RULE_RE = re.compile(
    r"^traefik\.http\.routers\.([^\.]+)\.rule$"
)


def get_docker_records(containers):
    """
    Discover DNS records from Docker labels.

    Required:

        traefik.http.routers.<name>.rule
        adguard.dns

    Example:

        traefik.http.routers.dozzle.rule=Host(`dozzle.nas.local`)
        adguard.dns=10.0.0.171
    """

    records = {}

    for container in containers:
        container_id = container["Id"]

        names = container.get("Names") or []
        container_name = (
            names[0].lstrip("/")
            if names
            else container_id[:12]
        )

        labels = container.get("Labels") or {}

        target = labels.get("adguard.dns")

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

            for hostname in hosts:
                key = rewrite_key(hostname, target)

                record = records.setdefault(
                    key,
                    {
                        "hostname": hostname,
                        "answer": target,
                        "owners": [],
                    },
                )

                owner = {
                    "source": "docker",
                    "container_id": container_id,
                    "container_name": container_name,
                    "router": router_name,
                }

                if owner not in record["owners"]:
                    record["owners"].append(owner)

    return records


# -----------------------------------------------------------------------------
# Dynamic Traefik config discovery
# -----------------------------------------------------------------------------

def get_traefik_target(containers):
    """
    The Traefik container's adguard.dns label is used as the target
    for routers discovered from the file provider.
    """

    for container in containers:
        names = container.get("Names") or []

        if "traefik" not in [
            name.lstrip("/").lower()
            for name in names
        ]:
            continue

        labels = container.get("Labels") or {}

        target = labels.get("adguard.dns")

        if target:
            return target.strip()

    return None


def iter_dynamic_files():
    if not os.path.isdir(DYNAMIC_CONFIG_DIR):
        log.warning(
            "Dynamic config directory does not exist: %s",
            DYNAMIC_CONFIG_DIR,
        )
        return

    for root, _, files in os.walk(DYNAMIC_CONFIG_DIR):
        for filename in sorted(files):
            if not filename.lower().endswith((".yml", ".yaml")):
                continue

            yield os.path.join(root, filename)


def get_file_records(containers):
    """
    Discover Host() rules from Traefik file-provider configs.

    The target comes from the Traefik container's adguard.dns label.
    """

    target = get_traefik_target(containers)

    if not target:
        log.warning(
            "Traefik container has no adguard.dns label; "
            "file-provider hosts will be ignored"
        )
        return {}

    records = {}

    for path in iter_dynamic_files():
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

        except Exception as exc:
            log.warning(
                "Unable to read dynamic config %s: %s",
                path,
                exc,
            )
            continue

        # We intentionally scan for Host() expressions rather than requiring
        # PyYAML. Traefik rules are strings embedded in YAML and this keeps
        # the companion dependency-free.
        for line_number, line in enumerate(
            content.splitlines(),
            start=1,
        ):
            if "Host(" not in line:
                continue

            hosts = extract_hosts(line)

            if not hosts:
                continue

            # Try to identify the router name from the preceding YAML.
            router_name = "unknown"

            for previous_line in reversed(
                content.splitlines()[:line_number - 1]
            ):
                match = re.match(
                    r"^\s{4}([A-Za-z0-9_.-]+):\s*$",
                    previous_line,
                )

                if match:
                    router_name = match.group(1)
                    break

                if re.match(
                    r"^\S",
                    previous_line,
                ):
                    break

            for hostname in hosts:
                key = rewrite_key(hostname, target)

                record = records.setdefault(
                    key,
                    {
                        "hostname": hostname,
                        "answer": target,
                        "owners": [],
                    },
                )

                owner = {
                    "source": "file",
                    "file": os.path.relpath(
                        path,
                        DYNAMIC_CONFIG_DIR,
                    ),
                    "router": router_name,
                }

                if owner not in record["owners"]:
                    record["owners"].append(owner)

                log.debug(
                    "Found file-provider host: %s -> %s "
                    "(%s:%d)",
                    hostname,
                    target,
                    os.path.relpath(
                        path,
                        DYNAMIC_CONFIG_DIR,
                    ),
                    line_number,
                )

    return records


# -----------------------------------------------------------------------------
# Desired records
# -----------------------------------------------------------------------------

def get_desired_records(containers):
    docker_records = get_docker_records(containers)
    file_records = get_file_records(containers)

    desired = docker_records

    for key, record in file_records.items():
        if key not in desired:
            desired[key] = record
        else:
            for owner in record["owners"]:
                if owner not in desired[key]["owners"]:
                    desired[key]["owners"].append(owner)

    log.info(
        "Discovered %d Docker records and %d file-provider records",
        len(docker_records),
        len(file_records),
    )

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
    # Delete ONLY records that were previously created/owned by us and are
    # no longer desired.
    # -------------------------------------------------------------------------

    stale_keys = previous_keys - desired_keys

    for key in sorted(stale_keys):
        record = previous_records[key]

        hostname = record["hostname"]
        answer = record["answer"]

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
    # Rebuild ownership state.
    # -------------------------------------------------------------------------

    new_records = {}

    for key, desired in sorted(desired_records.items()):
        hostname = desired["hostname"]
        answer = desired["answer"]

        previously_owned = key in previous_records
        exists = key in current_rewrites

        if exists:
            if previously_owned:
                new_records[key] = desired

                log.debug(
                    "Keeping owned rewrite: %s -> %s",
                    hostname,
                    answer,
                )

            else:
                # Existing record was not created by us.
                #
                # DO NOT claim it.
                # DO NOT modify it.
                # DO NOT delete it later.
                log.info(
                    "Leaving existing unowned rewrite untouched: "
                    "%s -> %s",
                    hostname,
                    answer,
                )

        else:
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

        if not os.path.isdir(DYNAMIC_CONFIG_DIR):
            raise RuntimeError(
                f"Dynamic config directory does not exist: "
                f"{DYNAMIC_CONFIG_DIR}"
            )

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
