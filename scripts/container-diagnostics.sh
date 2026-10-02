#!/usr/bin/env bash
# Bounded, non-secret failure diagnostics, emitted before fixture/container cleanup.
report_container_failure() {
 local stage="$1" status="$2" name="$3" workdir="$4"
 echo "container contract failed: stage=${stage} status=${status}" >&2
 docker inspect --format 'state={{.State.Status}} running={{.State.Running}} exitCode={{.State.ExitCode}} error={{.State.Error}}' "${name}" >&2 || true
 docker logs --tail 80 "${name}" >&2 || true
 if [ -n "${ORIGIN_NAME:-}" ]; then
  docker logs --tail 80 "${ORIGIN_NAME}" >&2 || true
 fi
 local kind
 for kind in http https; do
  if [ -s "${workdir}/${kind}.stderr" ]; then
   echo "${kind} origin stderr (last 80 lines):" >&2
   tail -n 80 "${workdir}/${kind}.stderr" >&2 || true
  fi
 done
}

# Follow the fixture's readiness event rather than polling a port file. The
# read deadline also covers a live container that never emits readiness.
wait_container_origin() {
 local name="$1" deadline="${2:-10}" ready logfd logpid
 coproc FIXTURE_LOGS { exec docker logs --follow "${name}"; }
 logfd="${FIXTURE_LOGS[0]:-}"
 logpid="${FIXTURE_LOGS_PID:-}"
 local result=1
 if [ -n "${logfd}" ] && IFS= read -r -t "${deadline}" -u "${logfd}" ready; then
  if [ "${ready}" = "origin ready http=:8080 https=:8443" ]; then result=0; fi
 fi
 if [ -n "${logpid}" ]; then
  kill "${logpid}" >/dev/null 2>&1 || true
  wait "${logpid}" 2>/dev/null || true
 fi
 if [ -n "${logfd}" ]; then exec {logfd}<&-; fi
 if [ "${result}" -ne 0 ]; then
  echo "origin did not emit valid readiness before exit or startup deadline: ${name}" >&2
 fi
 return "${result}"
}

# Bound every probe/smoke operation, including peers that accept TCP then stall.
container_curl() {
 curl --connect-timeout 2 --max-time 15 "$@"
}
