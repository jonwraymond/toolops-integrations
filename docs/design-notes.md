# Design Notes

## Why a separate repo?

Integrations often require heavier SDKs (Bitwarden, Vault, AWS) and can have additional security or operational constraints.
Keeping these out of `toolops` helps maintain a small core.

## Secret ref format

This repo targets the `secretref:<provider>:<ref>` format used by mcp-gateway.

