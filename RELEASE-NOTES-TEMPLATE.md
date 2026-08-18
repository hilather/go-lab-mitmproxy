# LabMITM VERSION Release Notes

Release date: YYYY-MM-DD
Previous release: PREVIOUS_VERSION
Application version: VERSION
Configuration versions: LIST
REST versions: LIST
MCP protocol versions: LIST
Container digest: DIGEST

## Highlights

Summarize the most important outcomes, not individual commits.

## Added

List every new user-visible or operator-visible capability.

## Changed

List every behavioral, default, performance, operational, or policy difference.

## Fixed

List correctness fixes, including proxy or TLS behavior whose observable output changed.

## Removed or deprecated

List removals, deprecations, replacement paths, and earliest removal versions.

## Security

List authentication, authorization, validation, hardening, dependency, CA/TLS, and vulnerability changes.

## Proxy behavior

Describe changes to modes, HTTP/1, HTTP/2, HTTP/3, WebSockets, CONNECT, upstream, SOCKS, intercept, replay, filters, transforms, and interoperability.

## TLS and certificates

Describe CA generation, leaf minting, upstream verification, mTLS, pinning workarounds, and onboarding (`mitm.it`) changes.

## REST API

Describe endpoint, schema, default, error, pagination, authorization, and compatibility differences.

## MCP API and protocol compatibility

Describe supported MCP protocol versions, SDK changes, tools, resources, schemas, errors, transport behavior, and migration requirements.

## Configuration and schema

Describe fields, defaults, validation, normalization, migrations, and canonical export differences.

## Deployment and operations

Describe images, ports, flags, environment variables, paths, health, resource guidance, and rollback differences.

## Observability

Describe metrics, labels, logs, traces, health semantics, and audit schemas.

## Compatibility and migration

Provide exact upgrade steps, breaking changes, compatibility windows, and rollback instructions.

## Known limitations

List unresolved limitations and safe workarounds.

## Complete functionality-difference review

Confirm that the generated differences below were reviewed and represented above:

- [ ] OpenAPI
- [ ] MCP capability manifest and tool/resource schemas
- [ ] Capability table
- [ ] Configuration schema and defaults
- [ ] CLI flags and environment variables
- [ ] Proxy mode and protocol support
- [ ] Error code catalog
- [ ] Metrics and labels
- [ ] Deployment files and image contents
- [ ] Dependencies and SBOM

## CI and release evidence

- [ ] All required CI passed on the exact tag commit.
- [ ] No required check was bypassed.
- [ ] Any CI failure encountered was fixed and hardened.
- [ ] Container digest maps to the tag commit.
- [ ] Security scans were reviewed.
- [ ] Upgrade and rollback were tested.
