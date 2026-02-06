# Architecture

`toolops-integrations` is intentionally dependency-heavy compared to `toolops`.

- `toolops` provides interfaces and resolution logic (`toolops/secret`).
- `toolops-integrations` provides implementations that talk to external systems.

This keeps core libraries light while allowing downstream applications to opt into integrations.

