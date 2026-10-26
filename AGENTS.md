# Repository Rules

- This is Anxin Code Signing Certificate Tool 1.0.44, licensed GPL-3.0-only.
- Keep the signing core frozen. Certificate discovery, signing modes, timestamping,
  Worker, file staging and signing orchestration require separate approval to change.
- Never commit keys, certificate exports, credentials, customer files or runtime logs.
- Use `scripts/test-public-source.ps1` for the default non-signing checks. Do not run
  the whole solution's tests blindly. Other test classes can access certificates,
  launch signing workers, install packages or interact with the desktop.
- Never automate production UI, installation, uninstallation, UAC, real signing,
  certificate providers, browser or clipboard interaction. The user owns those steps.
- Offscreen views with fake services and static MSI inspection are allowed.
- NSIS lifecycle tests may execute only the separately compiled AUTOMATED_TEST
  package, with fixed HKCU QA registration and isolated LocalAppData QA paths.
  Never run a production installer silently against the user's live installation.
- GPLv3 and company attribution are authorized. Do not publish or push without
  authorization. Preserve the original fixed 1.0.40 tree and installer.
- Keep .NET project identities; use lowercase-kebab-case for generic paths.
- Tests mirror the production layers. No production dependency on tests or tools.
- Build outputs belong under ignored `artifacts`, `.build`, `bin` or `obj`.
- Preserve existing work. Never reset, clean or overwrite a frozen release.
