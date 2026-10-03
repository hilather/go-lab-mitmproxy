#!/usr/bin/env bash
# Container contract for DEP-001. Requires Docker. Fail closed if the daemon
# is missing so this is a real check, not an unimplemented stub.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${LABMITM_TEST_IMAGE:-ghcr.io/hilather/labmitm:test}"
NAME="labmitm-container-test-$$"
ORIGIN_NAME="${NAME}-origin"
NETWORK="${NAME}-network"
ORIGIN_IMAGE="labmitm-container-origin:test"
COMPOSE="${ROOT}/examples/compose.smoke.yaml"
TOKEN="${ROOT}/testdata/container/token"
ORIGIN_CA="${ROOT}/testdata/tls/origin-ca.pem"
ORIGIN_CERT="${ROOT}/testdata/tls/origin.pem"
ORIGIN_KEY="${ROOT}/testdata/tls/origin-key.pem"

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is required for make test-container" >&2
	exit 1
fi
if ! docker info >/dev/null 2>&1; then
	echo "docker daemon is not available for make test-container" >&2
	exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
	echo "curl is required for make test-container" >&2
	exit 1
fi
if ! command -v go >/dev/null 2>&1; then
 echo "go is required to compile the test-only container origin" >&2
 exit 1
fi
if [ ! -f "${TOKEN}" ]; then
	echo "missing ${TOKEN}" >&2
	exit 1
fi
if [ ! -f "${ORIGIN_CA}" ] || [ ! -f "${ORIGIN_CERT}" ] || [ ! -f "${ORIGIN_KEY}" ]; then
	echo "missing HTTPS intercept fixture under testdata/tls/" >&2
	exit 1
fi

source "${ROOT}/scripts/container-diagnostics.sh"
STAGE="fixture startup"
WORKDIR="$(mktemp -d)"
cleanup() {
 local status=$?
 if [ "${status}" -ne 0 ]; then
  report_container_failure "${STAGE}" "${status}" "${NAME}" "${WORKDIR}"
 fi
	docker rm -f "${NAME}" >/dev/null 2>&1 || true
 docker rm -f "${ORIGIN_NAME}" >/dev/null 2>&1 || true
 docker network rm "${NETWORK}" >/dev/null 2>&1 || true
	rm -rf "${WORKDIR}"
}
trap cleanup EXIT

# Build before the bounded runtime readiness budget. Origin and appliance share
# an isolated bridge; no container-to-host INPUT firewall exception is needed.
STAGE="origin fixture build"
ORIGIN_ARCH="$(docker version --format '{{.Server.Arch}}')"
(
 cd "${ROOT}"
 CGO_ENABLED=0 GOOS=linux GOARCH="${ORIGIN_ARCH}" go build -o "${WORKDIR}/container-origin" ./scripts/containerorigin
)
cat > "${WORKDIR}/Dockerfile" <<'EOF'
FROM scratch
COPY container-origin /origin
USER 65532:65532
ENTRYPOINT ["/origin"]
EOF
docker build -t "${ORIGIN_IMAGE}" "${WORKDIR}"
docker network create "${NETWORK}" >/dev/null
STAGE="origin fixture startup"
docker run -d --name "${ORIGIN_NAME}" --network "${NETWORK}" --network-alias app.lab \
 --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
 -v "${ORIGIN_CERT}:/origin-cert.pem:ro" -v "${ORIGIN_KEY}:/origin-key.pem:ro" "${ORIGIN_IMAGE}" >/dev/null
wait_container_origin "${ORIGIN_NAME}"
HTTP_PORT=8080
HTTPS_PORT=8443

# extraCAFiles is validated at load, so the intercept overlay is written
# here (host testdata/container/config.yaml stays loadable without the
# in-container origin-ca path).
cat > "${WORKDIR}/config.yaml" <<EOF
apiVersion: labmitm.dev/v1alpha1
kind: LabMITM
metadata:
  name: container-smoke
spec:
  listeners:
    proxy:
      address: ":8888"
    management:
      address: ":8088"
      restPath: /v1
      mcpPath: /mcp
  tls:
    intercept: true
    ports: [443, ${HTTPS_PORT}]
    ca:
      mode: generate
    upstream:
      extraCAFiles:
        - /etc/labmitm/origin-ca.pem
  ui:
    enabled: false
  management:
    auth:
      mode: bearer
      tokens:
        - id: smoke
          secretFile: /etc/labmitm/token
          role: administrator
          scopes: [mitm.read, mitm.write, mitm.admin, mitm.audit.read]
  observability:
    logLevel: info
    metrics:
      listen: ""
      publicPath: false
EOF

STAGE="image build"
echo "building ${IMAGE}"
docker build -t "${IMAGE}" "${ROOT}"

STAGE="image metadata"
inspect_user="$(docker image inspect --format '{{.Config.User}}' "${IMAGE}")"
if [ "${inspect_user}" != "65532:65532" ]; then
	echo "image User=${inspect_user}, want 65532:65532" >&2
	exit 1
fi

licenses="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.licenses"}}' "${IMAGE}")"
if [ "${licenses}" != "Apache-2.0" ]; then
	echo "image license label=${licenses}, want Apache-2.0" >&2
	exit 1
fi

hc="$(docker image inspect --format '{{json .Config.Healthcheck.Test}}' "${IMAGE}")"
case "${hc}" in
*CMD-SHELL*)
	echo "image HEALTHCHECK=${hc} must be exec form, not shell" >&2
	exit 1
	;;
esac
case "${hc}" in
'["CMD",'*)
	;;
*)
	echo "image HEALTHCHECK=${hc}, want JSON array starting with CMD" >&2
	exit 1
	;;
esac
case "${hc}" in
*'/v1/health/ready'*)
	;;
*)
	echo "image HEALTHCHECK=${hc}, want /v1/health/ready" >&2
	exit 1
	;;
esac
case "${hc}" in
*healthcheck*)
	;;
*)
	echo "image HEALTHCHECK=${hc}, want exec-form labmitm healthcheck" >&2
	exit 1
	;;
esac
case "${hc}" in
*node*)
	echo "image HEALTHCHECK=${hc} must be HTTP ready, not node" >&2
	exit 1
	;;
esac

if docker compose version >/dev/null 2>&1; then
	docker compose -f "${COMPOSE}" config >/dev/null
else
	echo "docker compose plugin not available; compose file parse skipped" >&2
fi

STAGE="container startup"
docker run -d --name "${NAME}" \
	--read-only \
	--cap-drop=ALL \
	--security-opt=no-new-privileges:true \
	--network "${NETWORK}" \
	--tmpfs /tmp:rw,noexec,nosuid,size=16m \
	-v "${WORKDIR}/config.yaml:/etc/labmitm/config.yaml:ro" \
	-v "${TOKEN}:/etc/labmitm/token:ro" \
	-v "${ORIGIN_CA}:/etc/labmitm/origin-ca.pem:ro" \
	-p 127.0.0.1::8888/tcp \
	-p 127.0.0.1::8088/tcp \
	"${IMAGE}"

readonly_root="$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "${NAME}")"
if [ "${readonly_root}" != "true" ]; then
	echo "HostConfig.ReadonlyRootfs=${readonly_root}, want true" >&2
	exit 1
fi

assert_identity() {
	local uid capeef
	# Prefer in-container /proc/self/status (works when the client cannot
	# see the container PID, e.g. Docker Desktop / remote DOCKER_HOST).
	if status="$(docker exec "${NAME}" /labmitm debug-status 2>/dev/null)"; then
		uid="$(printf '%s\n' "${status}" | awk '/^Uid:/{print $2; exit}')"
		capeef="$(printf '%s\n' "${status}" | awk '/^CapEff:/{print $2; exit}')"
		if [ "${uid}" = "65532" ] && [ "${capeef}" = "0000000000000000" ]; then
			return 0
		fi
		echo "in-container Uid=${uid} CapEff=${capeef}, want 65532 / 0000000000000000" >&2
		return 1
	fi
	local pid
	pid="$(docker inspect --format '{{.State.Pid}}' "${NAME}")"
	if [ -r "/proc/${pid}/status" ]; then
		uid="$(awk '/^Uid:/{print $2}' "/proc/${pid}/status")"
		capeef="$(awk '/^CapEff:/{print $2}' "/proc/${pid}/status")"
		if [ "${uid}" = "65532" ] && [ "${capeef}" = "0000000000000000" ]; then
			return 0
		fi
		echo "host /proc Uid=${uid} CapEff=${capeef}, want 65532 / 0000000000000000" >&2
		return 1
	fi
	local capdrop privileged
	capdrop="$(docker inspect --format '{{json .HostConfig.CapDrop}}' "${NAME}")"
	privileged="$(docker inspect --format '{{.HostConfig.Privileged}}' "${NAME}")"
	case "${capdrop}" in
	*ALL*)
		;;
	*)
		echo "cannot read CapEff (need Linux Docker); CapDrop=${capdrop}, want ALL" >&2
		return 1
		;;
	esac
	if [ "${privileged}" != "false" ]; then
		echo "cannot read CapEff (need Linux Docker); Privileged=${privileged}, want false" >&2
		return 1
	fi
	echo "CapEff not readable from this client; accepted CapDrop=${capdrop} Privileged=${privileged}" >&2
	return 0
}
STAGE="container identity"
assert_identity

mgmt_port="$(docker port "${NAME}" 8088/tcp | head -n1 | awk -F: '{print $NF}')"
proxy_port="$(docker port "${NAME}" 8888/tcp | head -n1 | awk -F: '{print $NF}')"

STAGE="management readiness"
ok=0
ready_deadline=$((SECONDS + 10))
while [ "${SECONDS}" -lt "${ready_deadline}" ]; do
	if container_curl --connect-timeout 1 --max-time 1 -fsS "http://127.0.0.1:${mgmt_port}/v1/health/ready" >/dev/null 2>&1; then
		ok=1
		break
	fi
	sleep 0.25
done
if [ "${ok}" -ne 1 ]; then
	echo "management ready check failed on 127.0.0.1:${mgmt_port}" >&2
	docker logs "${NAME}" >&2 || true
	exit 1
fi

STAGE="container hardening"
# The image has no shell; docker exec still runs the copied binary.
if ! docker exec "${NAME}" /labmitm version >/dev/null; then
	echo "non-root exec of /labmitm version failed" >&2
	exit 1
fi
if ! docker exec "${NAME}" /labmitm healthcheck --url=http://127.0.0.1:8088/v1/health/ready >/dev/null; then
	echo "in-container HTTP ready healthcheck failed" >&2
	exit 1
fi
if docker exec "${NAME}" /bin/sh -c true >/dev/null 2>&1; then
	echo "image has a shell at /bin/sh" >&2
	exit 1
fi
if docker exec "${NAME}" /bin/busybox true >/dev/null 2>&1; then
	echo "image has busybox" >&2
	exit 1
fi
if ! docker exec "${NAME}" /labmitm debug-status --check-readonly >/dev/null; then
	echo "read-only root check failed (could write /probe-ro)" >&2
	exit 1
fi
if ! docker exec "${NAME}" /labmitm debug-status --check-system-certs >/dev/null; then
	echo "SystemCertPool check failed (missing ca-certificates.crt or empty pool)" >&2
	docker exec "${NAME}" /labmitm debug-status --check-system-certs >&2 || true
	exit 1
fi

SMOKE_TOKEN="$(tr -d '\r\n' < "${TOKEN}")"

STAGE="unauthenticated management"
unauth="$(container_curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${mgmt_port}/v1/flows")"
if [ "${unauth}" != "401" ]; then
	echo "unauthenticated GET /v1/flows status=${unauth}, want 401" >&2
	exit 1
fi

STAGE="HTTP proxy smoke"
http_body="$(container_curl -fsS --http1.1 --proxy "http://127.0.0.1:${proxy_port}" "http://app.lab:${HTTP_PORT}/container-smoke")"
if [ "${http_body}" != "container-smoke" ]; then
	echo "HTTP proxy smoke body=${http_body}, want container-smoke" >&2
	docker logs "${NAME}" >&2 || true
	exit 1
fi

STAGE="CA download"
container_curl -fsS -H "Authorization: Bearer ${SMOKE_TOKEN}" \
	"http://127.0.0.1:${mgmt_port}/v1/ca" > "${WORKDIR}/lab-ca.pem"
if ! grep -q 'BEGIN CERTIFICATE' "${WORKDIR}/lab-ca.pem"; then
	echo "GET /v1/ca did not return a PEM certificate" >&2
	exit 1
fi
if grep -q 'PRIVATE' "${WORKDIR}/lab-ca.pem"; then
	echo "GET /v1/ca leaked private key material" >&2
	exit 1
fi

STAGE="HTTPS intercept smoke"
https_body="$(container_curl -fsS --http1.1 --proxy "http://127.0.0.1:${proxy_port}" \
	--cacert "${WORKDIR}/lab-ca.pem" \
	"https://app.lab:${HTTPS_PORT}/container-smoke-https")"
if [ "${https_body}" != "container-smoke-https" ]; then
	echo "HTTPS intercept smoke body=${https_body}, want container-smoke-https" >&2
	docker logs "${NAME}" >&2 || true
	exit 1
fi

STAGE="captured flow contract"
listed="$(container_curl -fsS -H "Authorization: Bearer ${SMOKE_TOKEN}" "http://127.0.0.1:${mgmt_port}/v1/flows")"
if ! printf '%s\n' "${listed}" | grep -q 'container-smoke-https'; then
	echo "GET /v1/flows missing container-smoke-https: ${listed}" >&2
	exit 1
fi
if ! printf '%s\n' "${listed}" | grep -q '"intercepted":true'; then
	echo "GET /v1/flows missing intercepted=true: ${listed}" >&2
	exit 1
fi

echo "container contract ok image=${IMAGE}"
