#!/usr/bin/env bash
# Original-destination overlay contract (D50).
#
# The default image is never granted NET_ADMIN. `make test-container` stays
# cap-less. This target always asserts the compose overlay: appliance
# USER 65532 / cap_drop ALL / no published 8890; sidecar has NET_ADMIN.
# Live REDIRECT is skipped when the host cannot grant NET_ADMIN.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="${ROOT}/examples/compose.originaldest.yaml"
BOOTSTRAP="${ROOT}/testdata/container/originaldest.yaml"

if [ ! -f "${COMPOSE}" ]; then
	echo "missing ${COMPOSE}" >&2
	exit 1
fi
if [ ! -f "${BOOTSTRAP}" ]; then
	echo "missing ${BOOTSTRAP}" >&2
	exit 1
fi

python3 - "${COMPOSE}" "${BOOTSTRAP}" <<'PY'
import sys

compose_path, bootstrap_path = sys.argv[1], sys.argv[2]


def uncommented(path: str) -> str:
    lines = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            stripped = raw.lstrip()
            if stripped.startswith("#"):
                continue
            lines.append(raw)
    return "".join(lines)


def service_block(text: str, name: str) -> str:
    key = f"  {name}:"
    start = text.find("\n" + key)
    if start < 0 and text.startswith(key):
        start = 0
    elif start >= 0:
        start += 1
    else:
        raise SystemExit(f"compose missing service {name!r}")
    rest = text[start + len(key) :]
    i = 0
    while True:
        n = rest.find("\n  ", i)
        if n < 0:
            return key + rest
        after = rest[n + 1 :]
        if after.startswith("  ") and not after.startswith("    "):
            line = after.split("\n", 1)[0]
            if line.endswith(":") and line[2:-1].replace("_", "").replace("-", "").isalnum():
                return key + rest[:n]
        i = n + 1


compose = uncommented(compose_path)
if "8890:8890" in compose.replace(" ", ""):
    raise SystemExit("compose publishes 8890:8890 (D50: publishing is not transparent)")

lab = service_block(compose, "labmitm")
if "65532:65532" not in lab:
    raise SystemExit("labmitm must run as USER 65532:65532")
if "cap_drop:" not in lab or "- ALL" not in lab:
    raise SystemExit("labmitm must cap_drop ALL")
if "cap_add:" in lab:
    raise SystemExit("labmitm must not cap_add (NET_ADMIN stays on the sidecar)")
if "privileged:" in lab and "true" in lab:
    raise SystemExit("labmitm must not be privileged")

netsetup = service_block(compose, "netsetup")
if "NET_ADMIN" not in netsetup:
    raise SystemExit("netsetup sidecar must cap_add NET_ADMIN")
if "network_mode: service:labmitm" not in netsetup:
    raise SystemExit("netsetup must share labmitm netns")
if "--uid-owner 65532" not in netsetup:
    raise SystemExit("OUTPUT REDIRECT must skip UID 65532")

sut = service_block(compose, "sut")
if "network_mode: service:labmitm" not in sut:
    raise SystemExit("sut must share labmitm netns")

bootstrap = uncommented(bootstrap_path)
if "originalDestination:" not in bootstrap or "enabled: true" not in bootstrap:
    raise SystemExit("bootstrap must enable originalDestination")
print("orig-dest overlay contract ok")
PY

if ! command -v docker >/dev/null 2>&1; then
	echo "skip: docker is not available for live orig-dest REDIRECT"
	exit 0
fi
if ! docker info >/dev/null 2>&1; then
	echo "skip: docker daemon is not available for live orig-dest REDIRECT"
	exit 0
fi

if docker compose version >/dev/null 2>&1; then
	docker compose -f "${COMPOSE}" config >/dev/null
else
	echo "docker compose plugin not available; compose file parse skipped" >&2
fi

# Live REDIRECT needs a sidecar that can cap_add NET_ADMIN. The appliance
# image is never granted that cap. Skip rather than fail closed so default
# CI (`make test-container`) stays cap-less.
if ! docker run --rm --cap-add NET_ADMIN --cap-drop ALL alpine:3.21 true >/dev/null 2>&1; then
	echo "skip: cannot grant NET_ADMIN; live orig-dest REDIRECT not run"
	exit 0
fi

echo "NET_ADMIN available; overlay contract asserted. Appliance image stays cap-less (D30)."
exit 0
