#!/usr/bin/env python3

import base64
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

ADGUARD_URL = os.environ.get("ADGUARD_URL", "").rstrip("/")
ADGUARD_USERNAME = os.environ.get("ADGUARD_USERNAME", "")
ADGUARD_PASSWORD = os.environ.get("ADGUARD_PASSWORD", "")

TRAEFIK_API_URL = os.environ.get(
    "TRAEFIK_API_URL",
    "http://traefik:8080",
).rstrip("/")

DOCKER_SOCKET = "/var/run/docker.sock"

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))
STATE_FILE = os.environ.get("STATE_FILE", "/data/state.json")


# -----------------------------------------------------------------------------
# Traefik / Docker parsing
# -----------------------------------------------------------------------------

HOST_FUNCTION_RE = re.compile(
    r"Host\((.*?)\)",
    re.IGNORECASE,
)

HOST_VALUE_RE = re.compile(
    r"[`\"]([^`\"]+)[`\"]",
)

DOCKER_ROUTER_LABEL_RE = re.compile(
    r"^traefik\.http\.routers\.([^\.]+)\.rule$",
)

HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$"
)


# -----------------------------------------------------------------------------
# Generic HTTP
# -----------------------------------------------------------------------------

def http_request(
    url,
    method="GET",
    data=None,
    headers=None,
    timeout=10,
):
    request_headers = {
        "Accept": "application/json",
    }

    if headers:
        request_headers.update(headers)

    body = None

    if data is not None:
        body = json.dumps(data).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()

        if not raw:
            return None

        return json.loads(raw.decode("utf-8"))


# -----------------------------------------------------------------------------
# Docker Unix socket HTTP client
# -----------------------------------------------------------------------------

def docker_request(
    path,
    method="GET",
    data=None,
    timeout=10,
):
    body = None
    headers = {
        "Host": "localhost",
        "Accept": "application/json",
    }

    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        f"http://localhost{path}",
        data=body,
        headers=headers,
        method=method,
    )

    class UnixSocketHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(
                lambda host, timeout=10, **kwargs: UnixSocketConnection(
                    DOCKER_SOCKET,
                    timeout=timeout,
                ),
                req,
            )

    class UnixSocketConnection:
        def __init__(self, socket_path, timeout=10):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect(socket_path)

        def makefile(self, *args, **kwargs):
            return self.sock.makefile(*args, **kwargs)

        def close(self):
            self.sock.close()

    opener = urllib.request.build_opener(
        UnixSocketHTTPHandler()
    )

    with opener.open(request, timeout=timeout) as response:
        raw = response.read()

        if not raw:
            return None

        return json.loads(raw.decode("utf-8"))


# -----------------------------------------------------------------------------
# AdGuard client
# -----------------------------------------------------------------------------

def adguard_headers():
    credentials = f"{ADGUARD_USERNAME}:{ADGUARD_PASSWORD}"
    encoded = base64.b64encode(
        credentials.encode("utf-8")
    ).decode("ascii")

    return {
        "Authorization": f"Basic {encoded}",
    }


def adguard_request(
    path,
    method="GET",
    data=None,
):
    return http_request(
        f"{ADGUARD_URL}{path}",
        method=method,
        data=data,
        headers=adguard_headers(),
    )


def get_adguard_rewrites():
    response = adguard_request("/control/rewrite/list")

    if not isinstance(response, list):
        raise RuntimeError(
            f"Unexpected AdGuard rewrite response: {response!r}"
        )

    return response


def add_adguard_rewrite(domain, answer):
    adguard_request(
        "/control/rewrite/add",
        method="POST",
        data={
            "domain": domain,
            "answer": answer,
        },
    )


def delete_adguard_rewrite(domain, answer):
    adguard_request(
        "/control/rewrite/delete",
        method="POST",
        data={
            "domain": domain,
            "answer": answer,
        },
    )


# -----------------------------------------------------------------------------
# Traefik API
# -----------------------------------------------------------------------------

def get_traefik_routers():
    response = http_request(
        f"{TRAEFIK_API_URL}/api/http/routers"
    )

    if not isinstance(response, list):
        raise RuntimeError(
            f"Unexpected Traefik router response: {response!r}"
        )

    return response


# -----------------------------------------------------------------------------
# Docker discovery
# -----------------------------------------------------------------------------

def get_docker_containers():
    containers = docker_request("/containers/json?all=1")

    if not isinstance(containers, list):
        raise RuntimeError(
            f"Unexpected Docker container response: {containers!r}"
        )

    return containers


def container_name(container):
    names = container.get("Names") or []

    if not names:
        return ""

    return names[0].lstrip("/")


def get_container_labels(container):
    return container.get("Labels") or {}


def get_adguard_target(container):
    labels = get_container_labels(container)
    target = labels.get("adguard.dns", "").strip()

    if not target:
        return None

    return target


def build_docker_router_targets(containers):
    """
    Build:

        router name -> target IP

    from Docker labels.

    The Traefik API remains the source of truth for the actual router rule.
    These labels are only used to associate a Docker router with its
    adguard.dns target.
    """

    router_targets = {}

    for container in containers:
        labels = get_container_labels(container)
        target = labels.get("adguard.dns", "").strip()

        if not target:
            continue

        for label, value in labels.items():
            match = DOCKER_ROUTER_LABEL_RE.match(label)

            if not match:
                continue

            router_name = match.group(1)

            if not value:
                continue

            existing = router_targets.get(router_name)

            if existing and existing != target:
                print(
                    "WARNING: Docker router has conflicting adguard.dns "
                    f"targets: {router_name}: {existing} vs {target}"
                )
                continue

            router_targets[router_name] = target

    return router_targets


def get_traefik_container_target(containers):
    """
    File-provider routers do not have an adguard.dns label of their own.

    They use the target declared on the Traefik container itself.
    """

    for container in containers:
        name = container_name(container)

        if name == "traefik":
            target = get_adguard_target(container)

            if target:
                return target

    return None


# -----------------------------------------------------------------------------
# Host extraction
# -----------------------------------------------------------------------------

def extract_hosts(rule):
    """
    Extract exact Host() values.

    HostRegexp() is intentionally ignored.
    """

    if not rule:
        return []

    hosts = []

    for function_args in HOST_FUNCTION_RE.findall(rule):
        for value in HOST_VALUE_RE.findall(function_args):
            hostname = value.strip().lower().rstrip(".")

            if not hostname:
                continue

            if not HOSTNAME_RE.match(hostname):
                continue

            hosts.append(hostname)

    return sorted(set(hosts))


# -----------------------------------------------------------------------------
# Desired records
# -----------------------------------------------------------------------------

def get_desired_records(routers, containers):
    """
    Returns a set of:

        (hostname, target)

    Traefik API is the source of truth for the routers and rules.

    Docker labels are only used to determine the DNS target.
    """

    docker_router_targets = build_docker_router_targets(containers)
    traefik_target = get_traefik_container_target(containers)

    desired = set()

    for router in routers:
        rule = router.get("rule", "")
        provider = router.get("provider", "")
        name = router.get("name", "")

        hosts = extract_hosts(rule)

        if not hosts:
            continue

        target = None

        # ------------------------------------------------------------------
        # Docker provider
        # ------------------------------------------------------------------

        if provider == "docker":
            router_name = name

            if "@" in router_name:
                router_name = router_name.rsplit("@", 1)[0]

            target = docker_router_targets.get(router_name)

            if not target:
                print(
                    "WARNING: No adguard.dns target found for "
                    f"Docker router {name!r}; skipping"
                )
                continue

        # ------------------------------------------------------------------
        # File provider
        # ------------------------------------------------------------------

        elif provider == "file":
            target = traefik_target

            if not target:
                print(
                    "WARNING: No adguard.dns target found on Traefik "
                    "container; skipping file router "
                    f"{name!r}"
                )
                continue

        # ------------------------------------------------------------------
        # Unknown provider
        # ------------------------------------------------------------------

        else:
            print(
                f"WARNING: Unsupported Traefik router provider "
                f"{provider!r} for {name!r}; skipping"
            )
            continue

        for hostname in hosts:
            desired.add((hostname, target))

    return desired


# -----------------------------------------------------------------------------
# State
# -----------------------------------------------------------------------------

def load_state():
    path = Path(STATE_FILE)

    if not path.exists():
        return set()

    try:
        with path.open("r", encoding="utf-8") as file:
            state = json.load(file)

    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"WARNING: Could not load state file {STATE_FILE}: {exc}"
        )
        return set()

    owned = state.get("owned", [])

    result = set()

    for record in owned:
        if not isinstance(record, dict):
            continue

        domain = record.get("domain")
        answer = record.get("answer")

        if not domain or not answer:
            continue

        result.add(
            (
                domain.lower().rstrip("."),
                answer,
            )
        )

    return result


def save_state(owned):
    path = Path(STATE_FILE)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    records = [
        {
            "domain": domain,
            "answer": answer,
        }
        for domain, answer in sorted(owned)
    ]

    temporary = path.with_suffix(".tmp")

    with temporary.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "owned": records,
            },
            file,
            indent=2,
            sort_keys=True,
        )
        file.write("\n")

    temporary.replace(path)


# -----------------------------------------------------------------------------
# AdGuard rewrite normalization
# -----------------------------------------------------------------------------

def normalize_rewrites(rewrites):
    """
    Returns:

        (domain, answer) -> original rewrite object

    Only exact domain + answer pairs are considered equivalent.
    """

    result = {}

    for rewrite in rewrites:
        if not isinstance(rewrite, dict):
            continue

        domain = str(
            rewrite.get("domain", "")
        ).strip().lower().rstrip(".")

        answer = str(
            rewrite.get("answer", "")
        ).strip()

        if not domain or not answer:
            continue

        result[(domain, answer)] = rewrite

    return result


# -----------------------------------------------------------------------------
# Reconciliation
# -----------------------------------------------------------------------------

def reconcile():
    print("Refreshing Traefik routers...")

    routers = get_traefik_routers()
    containers = get_docker_containers()

    desired = get_desired_records(
        routers,
        containers,
    )

    print(
        f"Traefik routers: {len(routers)}, "
        f"desired DNS records: {len(desired)}"
    )

    rewrites = get_adguard_rewrites()
    existing = normalize_rewrites(rewrites)

    owned = load_state()

    # -------------------------------------------------------------------------
    # Remove stale records that WE own.
    #
    # Manual records are never touched because they are not in `owned`.
    # -------------------------------------------------------------------------

    stale = owned - desired

    for domain, answer in sorted(stale):
        key = (domain, answer)

        if key not in existing:
            print(
                f"Removing stale owned record: "
                f"{domain} -> {answer}"
            )
            owned.discard(key)
            continue

        print(
            f"Removing stale owned record: "
            f"{domain} -> {answer}"
        )

        try:
            delete_adguard_rewrite(
                domain,
                answer,
            )
        except Exception as exc:
            print(
                f"ERROR: Failed to delete "
                f"{domain} -> {answer}: {exc}"
            )
            continue

        owned.discard(key)
        existing.pop(key, None)

    # -------------------------------------------------------------------------
    # Ensure desired records exist.
    #
    # Critical ownership behavior:
    #
    #   Existing + owned     -> keep and remain owned
    #   Existing + unowned   -> leave untouched, DO NOT claim
    #   Missing              -> create and claim
    # -------------------------------------------------------------------------

    for domain, answer in sorted(desired):
        key = (domain, answer)

        # We already own this exact record.
        if key in owned:
            if key not in existing:
                print(
                    f"Recreating missing owned record: "
                    f"{domain} -> {answer}"
                )

                try:
                    add_adguard_rewrite(
                        domain,
                        answer,
                    )
                except Exception as exc:
                    print(
                        f"ERROR: Failed to recreate "
                        f"{domain} -> {answer}: {exc}"
                    )
                    continue

                existing[key] = {
                    "domain": domain,
                    "answer": answer,
                }

            continue

        # Someone already has this exact record.
        #
        # This may be a manually-created rewrite. We must NOT claim it.
        if key in existing:
            print(
                f"Existing unowned record preserved: "
                f"{domain} -> {answer}"
            )
            continue

        # Record does not exist. We can safely create and own it.
        print(
            f"Creating owned record: "
            f"{domain} -> {answer}"
        )

        try:
            add_adguard_rewrite(
                domain,
                answer,
            )
        except Exception as exc:
            print(
                f"ERROR: Failed to create "
                f"{domain} -> {answer}: {exc}"
            )
            continue

        owned.add(key)

        existing[key] = {
            "domain": domain,
            "answer": answer,
        }

    save_state(owned)

    print(
        f"Reconciliation complete: "
        f"{len(owned)} owned record(s)"
    )


# -----------------------------------------------------------------------------
# Healthcheck
# -----------------------------------------------------------------------------

def healthcheck():
    errors = []

    # Docker
    try:
        docker_request("/_ping")
    except Exception as exc:
        errors.append(
            f"Docker: {exc}"
        )

    # Traefik
    try:
        routers = get_traefik_routers()

        if not isinstance(routers, list):
            errors.append(
                "Traefik API returned invalid router data"
            )

    except Exception as exc:
        errors.append(
            f"Traefik: {exc}"
        )

    # AdGuard
    try:
        get_adguard_rewrites()
    except Exception as exc:
        errors.append(
            f"AdGuard: {exc}"
        )

    if errors:
        for error in errors:
            print(
                f"ERROR: {error}",
                file=sys.stderr,
            )

        return False

    print("OK")
    return True


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    if not ADGUARD_URL:
        print(
            "ERROR: ADGUARD_URL is not configured",
            file=sys.stderr,
        )
        sys.exit(1)

    if not ADGUARD_USERNAME:
        print(
            "ERROR: ADGUARD_USERNAME is not configured",
            file=sys.stderr,
        )
        sys.exit(1)

    if not ADGUARD_PASSWORD:
        print(
            "ERROR: ADGUARD_PASSWORD is not configured",
            file=sys.stderr,
        )
        sys.exit(1)

    if "--healthcheck" in sys.argv:
        sys.exit(
            0 if healthcheck() else 1
        )

    print("AdGuard DNS companion started")
    print(f"Traefik API: {TRAEFIK_API_URL}")
    print(f"AdGuard URL: {ADGUARD_URL}")
    print(f"Poll interval: {POLL_INTERVAL}s")
    print(f"State file: {STATE_FILE}")

    while True:
        try:
            reconcile()

        except KeyboardInterrupt:
            print("Stopping")
            return

        except Exception as exc:
            print(
                f"ERROR: Reconciliation failed: {exc}",
                file=sys.stderr,
            )

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
