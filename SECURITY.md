# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:

https://github.com/fastrevmd-lab/ssdf/security/advisories/new

(Security tab → "Report a vulnerability".) Do not email a vulnerability report
or send it through any third-party service — private GitHub Security
Advisories are the only reporting channel for this repository.

Include what you'd include in a bug report — affected version/commit,
reproduction steps, and impact — but keep it in the private advisory, not a
public issue, PR, discussion, or commit message.

## Scope

SSDF ingests, stores, and serves security telemetry (firewall/NGFW/SASE/IDaaS
logs, topology, and an audit trail) and exposes it to LLM agents through MCP
tools. Vulnerability classes we especially want to hear about:

- Anything that lets an MCP tool call read, write, or act beyond its
  authorized scope or tier (`sovereign` vs `public`), or bypass token/digest
  authentication.
- SQL/query injection in any of the ClickHouse query builders, including
  paths reachable only through an LLM-constructed query.
- Anything that would let ingested data (from Vector/VRL) affect the pipeline
  or database beyond being stored as an event — parser differentials,
  injection through unescaped log fields, etc.
- Any path that lets a model's output directly cause a security-relevant
  decision (an access grant, a config change, a query treated as
  authoritative) instead of being explained/drafted subject to deterministic
  code and human approval.
- Tampering with the hash-chained audit trail (`ssdf.audit`) that would not
  be detected by verification.
- Anything that would leak data outside the operator's own infrastructure —
  this project is meant to be self-hosted with no mandatory SaaS dependency,
  so an unexpected outbound/telemetry call is in scope even if it doesn't
  leak sensitive data.

## Response

This is a community-maintained project. There's no guaranteed SLA, but
reports are read and triaged by a human maintainer, not by any automated or
model-based process.
