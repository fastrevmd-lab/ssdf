# Token file format

Keys are **digests**, never tokens: `sha256:<hex>` of the bearer the client
sends. The server hashes what a caller presents and matches that, so it never
holds a secret it could leak, and this file cannot be turned back into working
credentials.

Mode must be `0600`. The loader refuses a group- or world-readable file at
startup rather than warning — once the process is serving, the exposure has
already happened.

## Mint a token

```
python -m ssdf_mcp_query.mint_token --principal triage-agent \
    --allowed-tools query_flows,top_talkers --days 90
```

The token is printed **once**, on stdout; the entry to paste goes to stderr.
It is not recoverable afterwards. That is the point of the change.

Omit `--allowed-tools` to grant every tool. `--days 0` means no expiry.

## Rotate

Add the new entry alongside the old, restart, move clients across, delete the
old entry, restart again. Two entries may coexist; two entries resolving to the
same digest may not, and the loader refuses that rather than silently letting
one shadow the other's grants.

## Migrating a legacy file

A key that is not a digest is treated as a plaintext token: it is hashed at load
so the deployment keeps working, and the principal is named in a startup warning
on stderr. Re-mint those tokens. **Treat every one of them as compromised** — a
leaked token and a live one are indistinguishable, which is exactly why they
should not have been stored in the first place.
