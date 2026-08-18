# Reviewer Checklist

## Design and scope

- [ ] Change matches a tracked task and normative design.
- [ ] Any invariant change has an ADR.
- [ ] Scope is coherent and no hidden public behavior is introduced.
- [ ] Independent rewrite: no copied mitmproxy source.

## Architecture

- [ ] REST/MCP adapters contain no independent business logic.
- [ ] Proxy does not import management packages.
- [ ] Candidate state is fully validated before atomic swap.
- [ ] Third-party HTTP/2, MCP, Starlark types remain behind adapters.

## Proxy / TLS correctness

- [ ] HTTP/1, CONNECT, H2, WS implications reviewed as applicable.
- [ ] Intercept hold/resume/kill cannot deadlock sessions.
- [ ] CA key not logged or exported accidentally.

## Security

- [ ] Authentication, authorization, input limits, and audit are correct.
- [ ] No secret leaks.
- [ ] Management defaults remain authenticated.

## Tests

- [ ] Every changed area has regression coverage.
- [ ] **Integration tests** added for new behavior.
- [ ] Bug fixes include a failing-before/passing-after test where practical.
- [ ] Parity tests updated when REST or MCP changes.
- [ ] No test was weakened to make CI pass.
- [ ] **CI is green**; any failure was fixed and hardened.

## Documentation and release

- [ ] All affected documentation is current.
- [ ] Unreleased notes describe externally visible behavior.

## Completion

- [ ] All required CI passes.
- [ ] Generated files are clean.
- [ ] Handoff is complete.
