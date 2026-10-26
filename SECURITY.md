# Security

Do not report credentials, certificate private keys, customer binaries or full
runtime logs in public issues. Prefer a redacted description and a minimal reproduction
using generated unsigned fixtures.

Before public launch, maintainers must enable private vulnerability reporting on
GitHub and publish a monitored security contact. Until then, use the existing private
support channel supplied with the product; do not publish an exploit or secret.

The default checks scan tracked paths and text for common credentials and private-key
markers. They are defense in depth, not a guarantee: binary/image contents, obfuscated
secrets, ownership of artwork and future Git history require human review.

No signing certificates or signing credentials belong in CI. The CI workflow has
read-only repository permission, performs non-signing checks, and never publishes releases.
